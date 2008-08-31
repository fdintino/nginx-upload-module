/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>

#include <ngx_http_upload.h>

#define NGX_UNZIP_MALFORMED NGX_UPLOAD_MALFORMED

#define LOCAL_DATA_HEADER_SIGNATURE         0x04034b50
#define ARCHIVE_EXTRA_DATA_SIGNATURE        0x08064b50
#define CENTRAL_FILE_HEADER_SIGNATURE       0x02014b50
#define DIGITAL_SIGNATURE_HEADER_SIGNATURE  0x05054b50
#define END_OF_CENTRAL_DIR_SIGNATURE        0x06054b50
#define SIGNATURE_LEN                       4 
#define LOCAL_DATA_HEADER_LEN               30
#define FILE_HEADER_LEN                     46
#define DATA_DESCRIPTOR_LEN                 12
#define END_OF_CENTRAL_DIR_LEN              18

#define ZIP_METHOD_STORED                   0
#define ZIP_METHOD_DEFLATED                 8

#define ZIP_FLAG_ENCRYPTED                  0x0001
#define ZIP_FLAG_UNLIMITED                  0x0008
#define ZIP_FLAG_RESERVED1                  0x0010
#define ZIP_FLAG_PATCH                      0x0020
#define ZIP_FLAG_STRONG_ENCRYPTION          0x0040
#define ZIP_FLAG_USE_UTF8                   0x0800
#define ZIP_FLAG_RESERVED2                  0x1000
#define ZIP_FLAG_LOCAL_HEADER_OBFUSCATED    0x2000
#define ZIP_FLAG_RESERVED3                  0x4000
#define ZIP_FLAG_RESERVED4                  0x8000

#define ZIP_VERSION                         20

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)
#define EXTRACT_SHORT(x) (uint16_t)(*(x) | *((x)+1) << 8)
#define EXTRACT_LONG(x) (uint32_t)(*(x) | *((x)+1) << 8 | *((x)+2) << 16 | *((x)+3) << 24)
#else
#define EXTRACT_SHORT(x) (uint16_t)(*(x) << 8 | *((x)+1))
#define EXTRACT_LONG(x) (uint32_t)(*(x) << 24 | *((x)+1) << 16 | *((x)+2) << 8 | *((x)+3))
#endif

struct ngx_unzip_ctx_s;

typedef struct {
    uint16_t method;
    ngx_int_t (*start)(struct ngx_unzip_ctx_s*);
    void (*finish)(struct ngx_unzip_ctx_s*);
    void (*abort)(struct ngx_unzip_ctx_s*);
    ngx_int_t (*process_chain)(struct ngx_unzip_ctx_s*, ngx_chain_t*);
} ngx_unzip_decompression_method_t;

#define ngx_unzip_decompression_method_null { 0xffff, NULL, NULL, NULL, NULL }

typedef struct {
    ngx_bufs_t           bufs;
    size_t               wbits;
    size_t               max_file_name_len;
    unsigned int         recursive:1;
} ngx_unzip_conf_t;

typedef enum {
    unzip_state_signature,
    unzip_state_local_data_header,
    unzip_state_file_name,
    unzip_state_extra_field,
    unzip_state_file_data,
    unzip_state_unlimited_file_data,
    unzip_state_data_descriptor,
    unzip_state_decryption_header,
    unzip_state_extra_data_record,
    unzip_state_file_header,
    unzip_state_digital_sig_header,
    unzip_state_central_directory_end,
    unzip_state_finish
} ngx_unzip_state_e;

typedef struct {
    uint16_t            version_needed;
    uint16_t            flags;
    uint16_t            compression_method;
    uint16_t            last_mod_time;
    uint16_t            last_mod_date;
    uint32_t            crc32;
    size_t              compressed_size;
    size_t              uncompressed_size;
    size_t              file_name_len;
    size_t              extra_field_len;
} ngx_unzip_local_data_header_t;

typedef struct {
    uint16_t            version_made_by;
    uint16_t            version_needed;
    uint16_t            flags;
    uint16_t            compression_method;
    uint16_t            last_mod_time;
    uint16_t            last_mod_date;
    uint32_t            crc32;
    size_t              compressed_size;
    size_t              uncompressed_size;
    size_t              file_name_len;
    size_t              extra_field_len;
    size_t              file_comment_len;
    uint16_t            disk_number_start;
    uint16_t            internal_file_attributes;
    uint16_t            external_file_attributes;
    off_t               relative_offset;
} ngx_unzip_file_data_header_t;

typedef struct {
    size_t              data_size;
} ngx_unzip_digital_signature_t;

typedef struct {
    uint16_t            version_made_by;
    uint16_t            version_needed;
    uint16_t            flags;
    uint16_t            compression_method;
    uint16_t            last_mod_time;
    uint16_t            last_mod_date;
    uint32_t            crc32;
    size_t              compressed_size;
    size_t              uncompressed_size;
    size_t              file_name_len;
    size_t              extra_field_len;
    size_t              file_comment_len;
    uint16_t            disk_number_start;
    uint16_t            internal_file_attrs;
    uint16_t            external_file_attrs;
    off_t               relative_offset;
} ngx_unzip_end_of_central_dir_t;

typedef struct ngx_unzip_ctx_s {
    struct ngx_unzip_ctx_s *parent;

    ngx_unzip_state_e   state;
    size_t              current_field_len;
    size_t              current_field_pos;

    ngx_pool_t          *pool;
    ngx_log_t           *log;

    u_char              accumulator[512];

    u_char              *current_field;
    u_char              *current_field_ptr;

    uint16_t            version_needed;
    uint16_t            flags;
    uint16_t            compression_method;
    uint16_t            last_mod_time;
    uint16_t            last_mod_date;
    uint32_t            crc32;
    size_t              compressed_size;
    size_t              uncompressed_size;
    size_t              file_name_len;
    size_t              extra_field_len;

    ngx_str_t           file_name;

    z_stream            stream;

    ngx_buf_t           *output_buffer;
    ngx_chain_t         *output_chain;

    ngx_http_upload_ctx_t       *upload_ctx;
    ngx_upload_content_filter_t *next_content_filter; 
    ngx_unzip_decompression_method_t *decompression_method;

    uint32_t            calculated_crc32;

    unsigned int        discard_data:1;
} ngx_unzip_ctx_t;

static char * ngx_http_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_unzip_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_unzip_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u);
static ngx_int_t ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u,
    ngx_chain_t *chain);

static ngx_int_t ngx_http_unzip_retrieve_start(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_retrieve_finish(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_retrieve_abort(ngx_unzip_ctx_t *ctx);
static ngx_int_t ngx_http_unzip_retrieve_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain);

static ngx_int_t ngx_http_unzip_inflate_start(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_inflate_finish(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_inflate_abort(ngx_unzip_ctx_t *ctx);
static ngx_int_t ngx_http_unzip_inflate_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain);

static char *ngx_http_unzip_window(ngx_conf_t *cf, void *post, void *data);

static ngx_int_t
ngx_http_unzip_set_decompression_method(ngx_unzip_ctx_t *ctx, uint16_t compression_method_number);
static ngx_int_t ngx_http_unzip_parse_file_name(ngx_unzip_ctx_t *ctx, ngx_str_t *file_name);

static ngx_unzip_decompression_method_t /* {{{ */
ngx_unzip_decompression_methods[] = {

    { ZIP_METHOD_STORED,
      ngx_http_unzip_retrieve_start,
      ngx_http_unzip_retrieve_finish,
      ngx_http_unzip_retrieve_abort,
      ngx_http_unzip_retrieve_process_chain },

    { ZIP_METHOD_DEFLATED,
      ngx_http_unzip_inflate_start,
      ngx_http_unzip_inflate_finish,
      ngx_http_unzip_inflate_abort,
      ngx_http_unzip_inflate_process_chain },

    ngx_unzip_decompression_method_null
} /* }}} */;

static ngx_upload_content_filter_t /* {{{ */
ngx_http_unzip_content_filter = {
    ngx_http_unzip_start_handler,
    ngx_http_unzip_finish_handler,
    ngx_http_unzip_abort_handler,
    ngx_http_unzip_data_handler
} /* }}} */;

static ngx_conf_post_handler_pt  ngx_http_unzip_window_p = ngx_http_unzip_window;

static ngx_command_t  ngx_http_unzip_filter_commands[] = { /* {{{ */

    /*
     * Enables unzipping of uploaded file
     */
    { ngx_string("unzip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_unzip_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies size and number of buffers to use for decompressing
     */
    { ngx_string("unzip_buffers"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, bufs),
      NULL },

    /*
     * Specifies size window to use for decompressing
     */
    { ngx_string("unzip_window"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, wbits),
      &ngx_http_unzip_window_p },

    /*
     * Specifies a form field with a special content to generate
     * in output form
     */
    { ngx_string("unzip_set_form_field"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, wbits),
      NULL },

    /*
     * Specifies a form field with a special aggregate content to generate
     * in output form
     */
    { ngx_string("unzip_aggregate_form_field"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, wbits),
      NULL },

    /*
     * Specifies the maximal length of a file name in archive
     */
    { ngx_string("unzip_max_file_name_len"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, max_file_name_len),
      NULL },

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_http_unzip_filter_module_ctx = { /* {{{ */
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_unzip_create_loc_conf,        /* create location configuration */
    NULL                                   /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_http_unzip_filter_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_unzip_filter_module_ctx,     /* module context */
    ngx_http_unzip_filter_commands,        /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
}; /* }}} */

static char * /* {{{ ngx_http_unzip_command */
ngx_http_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_unzip_conf_t           *uzcf = conf;
    ngx_http_upload_loc_conf_t *ulcf;

    ngx_str_t                   *value;

    ulcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upload_module);

    value = cf->args->elts;

    if(cf->args->nelts > 1) {
        if(ngx_strcmp(value[1].data, "recursive") == 0) {
            uzcf->recursive = 1;
        }
    }

    if(ngx_http_upload_add_filter(ulcf, &ngx_http_unzip_content_filter, cf->pool) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_process_chain */
ngx_http_unzip_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain) {
    ngx_int_t result;
    ngx_buf_t *buf;
    ngx_unzip_conf_t *uzcf;

    uzcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_http_unzip_filter_module); 

    while(chain != NULL) {
        for(buf = chain->buf ; buf->pos != buf->last ; buf->pos++) {
            switch(ctx->state) {
                case unzip_state_signature: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = SIGNATURE_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        switch(EXTRACT_LONG(ctx->current_field)) {
                            case LOCAL_DATA_HEADER_SIGNATURE:
                                ctx->state = unzip_state_local_data_header;
                                break;
                            case ARCHIVE_EXTRA_DATA_SIGNATURE:
                                ctx->state = unzip_state_local_data_header;
                                break;
                            case CENTRAL_FILE_HEADER_SIGNATURE:
                                ctx->state = unzip_state_file_header;
                                break;
                            case DIGITAL_SIGNATURE_HEADER_SIGNATURE:
                                ctx->state = unzip_state_digital_sig_header;
                                break;
                            default:
                                return NGX_UNZIP_MALFORMED;
                        }
                    }
                    break; /* }}} */
                case unzip_state_local_data_header: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = LOCAL_DATA_HEADER_LEN - SIGNATURE_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;

                        ctx->discard_data = 0;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;

                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        ctx->version_needed = EXTRACT_SHORT(ctx->current_field);
                        ctx->flags = EXTRACT_SHORT(ctx->current_field + 2);
                        ctx->compression_method = EXTRACT_SHORT(ctx->current_field + 4);
                        ctx->last_mod_time = EXTRACT_SHORT(ctx->current_field + 6);
                        ctx->last_mod_date = EXTRACT_SHORT(ctx->current_field + 8);
                        ctx->crc32 = EXTRACT_LONG(ctx->current_field + 10);
                        ctx->compressed_size = EXTRACT_LONG(ctx->current_field + 14);
                        ctx->uncompressed_size = EXTRACT_LONG(ctx->current_field + 18);

                        ctx->file_name_len = EXTRACT_SHORT(ctx->current_field + 22);
                        ctx->extra_field_len = EXTRACT_SHORT(ctx->current_field + 24);

                        if(uzcf->max_file_name_len > 0 && ctx->file_name_len > uzcf->max_file_name_len) {
                            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                                  "file name in is too long: %u", ctx->file_name_len);
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ngx_http_unzip_set_decompression_method(ctx,
                            ctx->compression_method) != NGX_OK) 
                        {
                            return NGX_UNZIP_MALFORMED;
                        } 

                        if(ctx->version_needed > ZIP_VERSION)
                        {
                            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                                  "more recent version of unzip implementation required: %u, have %u", ctx->version_needed, ZIP_VERSION);
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ctx->file_name_len > 0)
                            ctx->state = unzip_state_file_name;
                        else if(ctx->extra_field_len > 0)
                            ctx->state = unzip_state_extra_field;
                        else if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break; /* }}} */
                case unzip_state_file_name: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->file_name.len = ctx->file_name_len;

                        ctx->file_name.data = ngx_palloc(ctx->pool, ctx->file_name_len);

                        if(ctx->file_name.data == NULL) {
                            return NGX_UPLOAD_NOMEM;
                        }

                        ctx->current_field_len = ctx->file_name_len;
                        ctx->current_field_ptr = ctx->current_field = ctx->file_name.data;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ngx_http_unzip_parse_file_name(ctx, &ctx->file_name) != NGX_OK) {
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ctx->extra_field_len > 0)
                            ctx->state = unzip_state_extra_field;
                        else if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break; /* }}} */
                case unzip_state_extra_field:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->extra_field_len;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_file_data: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->compressed_size;

                        if(ctx->decompression_method->start(ctx) != NGX_OK) {
                            ctx->discard_data = 1;
                        }
                    }
        
                    if(!ctx->discard_data) {
                        result = ctx->decompression_method->process_chain(ctx, chain);

                        buf->pos--;

                        if(result == NGX_AGAIN) {
                            return NGX_AGAIN;
                        }

                        if(result != NGX_OK) {
                            ctx->discard_data = 1;

                            ctx->decompression_method->abort(ctx);

                            ctx->current_field_pos++;
                        }
                    }else
                        ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos >= ctx->current_field_len) {
                        if(!ctx->discard_data)
                            ctx->decompression_method->finish(ctx);

                        ctx->current_field_pos = 0;

                        ctx->state = unzip_state_signature;
                    }
                    break; /* }}} */
                case unzip_state_unlimited_file_data: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        if(ctx->decompression_method->start(ctx) != NGX_OK) {
                            ctx->discard_data = 1;
                        }

                        ctx->current_field_pos = 1;
                    }
        
                    if(!ctx->discard_data) {
                        result = ctx->decompression_method->process_chain(ctx, chain);

                        buf->pos--;

                        if(result == NGX_AGAIN) {
                            return NGX_AGAIN;
                        }

                        if(result != NGX_OK) {
                            ctx->discard_data = 1;

                            ctx->decompression_method->abort(ctx);

                            return NGX_UNZIP_MALFORMED;
                        }else{
                            if(!ctx->discard_data)
                                ctx->decompression_method->finish(ctx);

                            ctx->current_field_pos = 0;

                            ctx->state = unzip_state_data_descriptor;
                        }
                    }
                    break; /* }}} */
                case unzip_state_data_descriptor:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = DATA_DESCRIPTOR_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        ctx->crc32 = EXTRACT_LONG(ctx->current_field);
                        ctx->compressed_size = EXTRACT_LONG(ctx->current_field + 4);
                        ctx->uncompressed_size = EXTRACT_LONG(ctx->current_field + 8);

                        ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_decryption_header:
                    break;
                case unzip_state_extra_data_record:
                    break;
                case unzip_state_file_header:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = FILE_HEADER_LEN - SIGNATURE_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;
                        ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_digital_sig_header:
                    break;
                case unzip_state_central_directory_end:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = END_OF_CENTRAL_DIR_LEN - SIGNATURE_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;
                        ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_finish:
                    break;
            }
        }

        chain = chain->next;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_start_handler */
ngx_http_unzip_start_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_conf_t           *uzcf;
    ngx_unzip_ctx_t            *ctx, *parent;

    uzcf = ngx_http_get_module_loc_conf(u->request, ngx_http_unzip_filter_module);

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    parent = ctx;

    ctx = ngx_pcalloc(u->request->pool, sizeof(ngx_unzip_ctx_t));
    if (ctx == NULL) {
        return NGX_UPLOAD_NOMEM;
    }

    ctx->parent = parent;

    ngx_http_set_ctx(u->request, ctx, ngx_http_unzip_filter_module);

    ctx->state = unzip_state_signature;
    ctx->upload_ctx = u;
    ctx->next_content_filter = ngx_upload_get_next_content_filter(u);

    ctx->pool = u->request->pool; 
    ctx->log = u->log; 

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_unzip_finish_handler */
ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    if (ctx->state == unzip_state_file_data) {
        if(!ctx->discard_data)
            ctx->decompression_method->abort(ctx);
    }

    ngx_http_set_ctx(u->request, ctx->parent, ngx_http_unzip_filter_module);
} /* }}} */

static void /* {{{ ngx_http_unzip_abort_handler */
ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    if (ctx->state == unzip_state_file_data) {
        if(!ctx->discard_data)
            ctx->decompression_method->abort(ctx);
    }

    ngx_http_set_ctx(u->request, ctx->parent, ngx_http_unzip_filter_module);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_data_handler */
ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u, ngx_chain_t *chain) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    return ngx_http_unzip_process_chain(ctx, chain);
} /* }}} */

static void * /* {{{ ngx_http_unzip_create_loc_conf */
ngx_http_unzip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_unzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_unzip_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->wbits = 15;
    conf->bufs.num = 4;
    conf->bufs.size = ngx_pagesize;

    /*
     * conf->bufs
     * zeroed by ngx_pcalloc
     */

    return conf;
} /* }}} */

static char * /* {{{ ngx_http_unzip_window */
ngx_http_unzip_window(ngx_conf_t *cf, void *post, void *data)
{
    int *np = data;

    int  wbits, wsize;

    wbits = 15;

    for (wsize = 32 * 1024; wsize > 256; wsize >>= 1) {

        if (wsize == *np) {
            *np = wbits;

            return NGX_CONF_OK;
        }

        wbits--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, or 32k";
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_set_decompression_method */
ngx_http_unzip_set_decompression_method(ngx_unzip_ctx_t *ctx, uint16_t compression_method)
{
    ngx_unzip_decompression_method_t *m = ngx_unzip_decompression_methods; 

    while(m->method != 0xffff) {
        if(m->method== compression_method) {
            ctx->decompression_method = m;
            return NGX_OK;
        }

        m++;
    }

    ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
          "unknown compression method: %u", compression_method);

    return NGX_ERROR;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_inflate_start */
ngx_http_unzip_inflate_start(ngx_unzip_ctx_t *ctx) {
    ngx_int_t rc;
    ngx_unzip_conf_t           *uzcf;

    ctx->stream.zalloc = Z_NULL;
    ctx->stream.zfree = Z_NULL;
    ctx->stream.opaque = Z_NULL;
    ctx->stream.avail_in = 0;
    ctx->stream.next_in = Z_NULL;

    uzcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_http_unzip_filter_module); 

    if(ctx->output_buffer == NULL) {
        ctx->output_buffer = ngx_create_temp_buf(ctx->pool, uzcf->bufs.size);

        if (ctx->output_buffer == NULL) {
            return NGX_ERROR;
        }
    }

    if(ctx->output_chain == NULL) {
        ctx->output_chain = ngx_alloc_chain_link(ctx->pool);

        if (ctx->output_chain == NULL) {
            return NGX_ERROR;
        }

        ctx->output_chain->buf = ctx->output_buffer;
        ctx->output_chain->next = NULL;
    }

    rc = inflateInit2(&ctx->stream, -uzcf->wbits);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
              "inflateInit() failed: %d", rc);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "started inflating file \"%V\"", &ctx->file_name);

    if(ctx->next_content_filter->start) {
        rc = ctx->next_content_filter->start(ctx->upload_ctx);

        if(rc != NGX_OK) {
            goto cleanup;
        }

        return rc;
    }

    ngx_crc32_init(ctx->calculated_crc32);

    return NGX_OK;
cleanup:
    inflateEnd(&ctx->stream);    
    return rc;
} /* }}} */

static void /* {{{ ngx_http_unzip_inflate_finish */
ngx_http_unzip_inflate_finish(ngx_unzip_ctx_t *ctx) {
    ngx_crc32_final(ctx->calculated_crc32);

    if(ctx->next_content_filter->finish)
        ctx->next_content_filter->finish(ctx->upload_ctx);

    inflateEnd(&ctx->stream);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "finished inflating file \"%V\"", &ctx->file_name);
} /* }}} */

static void /* {{{ ngx_http_unzip_inflate_abort */
ngx_http_unzip_inflate_abort(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->abort)
        ctx->next_content_filter->abort(ctx->upload_ctx);

    inflateEnd(&ctx->stream);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "aborted inflating file \"%V\"", &ctx->file_name);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_inflate_process_chain */
ngx_http_unzip_inflate_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain) {
    int rc;
    size_t remaining;

    while(chain != NULL && !chain->buf->last_in_chain) {
        remaining = chain->buf->last - chain->buf->pos;

        if(ctx->current_field_len - ctx->current_field_pos > remaining)
            ctx->stream.avail_in = remaining;
        else
            ctx->stream.avail_in = ctx->current_field_len - ctx->current_field_pos;

        ctx->stream.next_in = chain->buf->pos;

        do{
            ctx->stream.avail_out = ctx->output_buffer->end - ctx->output_buffer->start;
            ctx->stream.next_out = ctx->output_buffer->pos = ctx->output_buffer->start;

            rc = inflate(&ctx->stream, Z_NO_FLUSH);

            if(rc == Z_OK || rc == Z_STREAM_END) {
                ctx->output_buffer->last = ctx->stream.next_out;

                ngx_crc32_update(&ctx->calculated_crc32, ctx->output_buffer->pos, 
                    ctx->output_buffer->last - ctx->output_buffer->pos);

                if(ctx->next_content_filter->process_chain)
                    ctx->next_content_filter->process_chain(ctx->upload_ctx, 
                        ctx->output_chain);
            }

            if(rc == Z_STREAM_END) {
                break;
            }

            if (rc != Z_OK) {
                ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                      "inflate() failed: %d", rc);
                return NGX_ERROR;
            }
        }while(ctx->stream.avail_out == 0 && rc == Z_OK);

        ctx->current_field_pos += (ctx->stream.next_in - chain->buf->pos);

        chain->buf->pos = ctx->stream.next_in;

        if(rc == Z_STREAM_END) {
            break;
        }

        chain = chain->next;
    }

    if(ctx->current_field_len - ctx->current_field_pos == 0)
        return NGX_OK;
    else
        return NGX_AGAIN;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_retrieve_start */
ngx_http_unzip_retrieve_start(ngx_unzip_ctx_t *ctx) {
    ngx_int_t rc;

    rc = ngx_upload_set_file_name(ctx->upload_ctx, &ctx->file_name);

    if(rc != NGX_OK)
        return rc;

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "started retrieving file \"%V\"", &ctx->file_name);

    if(ctx->next_content_filter->start)
        return ctx->next_content_filter->start(ctx->upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_unzip_retrieve_finish */
ngx_http_unzip_retrieve_finish(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->finish)
        ctx->next_content_filter->finish(ctx->upload_ctx);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "finished retrieving file \"%V\"", &ctx->file_name);
} /* }}} */

static void /* {{{ ngx_http_unzip_retrieve_abort */
ngx_http_unzip_retrieve_abort(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->abort)
        ctx->next_content_filter->abort(ctx->upload_ctx);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "aborted retrieving file \"%V\"", &ctx->file_name);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_retrieve_process_chain */
ngx_http_unzip_retrieve_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain) {
    ngx_chain_t *cl;

    if(ctx->next_content_filter->process_chain) {
        for(cl = chain; cl; cl = cl->next)
            ctx->current_field_pos += (cl->buf->pos - cl->buf->last);

        return ctx->next_content_filter->process_chain(ctx->upload_ctx, chain); 
    }else
        return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_parse_file_name */
ngx_http_unzip_parse_file_name(ngx_unzip_ctx_t *ctx, ngx_str_t *file_name) {
    u_char *p;
    ngx_int_t rc;

    ngx_str_t archive_path = { file_name->len, file_name->data };
    ngx_str_t element_name = { file_name->len, file_name->data };
    ngx_str_t exten;
    ngx_str_t content_type;

    for(p = file_name->data + file_name->len - 1; p >= file_name->data ; p--, archive_path.len--) {
        if(*p == '/') {
            element_name.data = p + 1;
            element_name.len = file_name->len - (p - file_name->data) - 1;

            goto set;
        }
    }

    archive_path.len = 0;

set:
    rc = ngx_upload_set_file_name(ctx->upload_ctx, &element_name);

    if(rc != NGX_OK) {
        return rc;
    }

    rc = ngx_upload_set_exten(ctx->upload_ctx, &element_name, &exten);

    if(rc != NGX_OK) {
        return rc;
    }

    rc = ngx_upload_resolve_content_type(ctx->upload_ctx, &exten, &content_type);

    if(rc != NGX_OK) {
        return rc;
    }

    rc = ngx_upload_set_content_type(ctx->upload_ctx, &content_type);

    if(rc != NGX_OK) {
        return rc;
    }

    rc = ngx_upload_set_archive_path(ctx->upload_ctx, &archive_path);

    if(rc != NGX_OK) {
        return rc;
    }

    return NGX_OK;
} /* }}} */

