/*
 * Copyright (C) 2008 Valery Kholodkov
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <zlib.h>

#include <ngx_http_upload.h>

#define NGX_UNZIP_MALFORMED NGX_UPLOAD_MALFORMED

#define LOCAL_DATA_HEADER_SIGNATURE         0x04034b50
#define CENTRAL_FILE_HEADER_SIGNATURE       0x02014b50
#define DIGITAL_SIGNATURE_HEADER_SIGNATURE  0x05054b50
#define END_OF_CENTRAL_DIR_SIGNATURE        0x06054b50
#define EXTRA_DATA_RECORD_SIGNATURE         0x08064b50
#define SIGNATURE_LEN                       4 
#define LOCAL_DATA_HEADER_LEN               30
#define FILE_HEADER_LEN                     46
#define DATA_DESCRIPTOR_LEN                 12
#define END_OF_CENTRAL_DIR_LEN              18
#define DIGITAL_SIGNATURE_HEADER_LEN        6
#define EXTRA_DATA_RECORD_LEN               8

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
    size_t               wbits, memlevel;
    size_t               max_file_name_len;
} ngx_unzip_loc_conf_t;

typedef enum {
    unzip_state_signature,
    unzip_state_local_data_header,
    unzip_state_file_name,
    unzip_state_extra_field,
    unzip_state_file_data,
    unzip_state_unlimited_file_data,
    unzip_state_data_descriptor,
    unzip_state_extra_data_record,
    unzip_state_extra_data_record_data,
    unzip_state_file_header,
    unzip_state_file_header_file_name,
    unzip_state_file_header_extra_field,
    unzip_state_file_header_file_comment,
    unzip_state_digital_sig_header,
    unzip_state_digital_sig,
    unzip_state_central_directory_end,
    unzip_state_archive_comment,
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
    uint16_t            internal_file_attrs;
    uint16_t            external_file_attrs;
    off_t               relative_offset;
} ngx_unzip_file_header_t;

typedef struct {
    size_t              data_size;
} ngx_unzip_digital_sig_t;

typedef struct {
    size_t              extra_field_len;
} ngx_unzip_extra_data_record_t;

typedef struct {
    uint16_t            disk_number;
    uint16_t            number_of_disk_with_start_of_dir;
    uint16_t            number_of_entries_on_this_disk;
    uint16_t            total_number_of_entries;
    size_t              size_of_directory;
    size_t              offset_of_start;
    uint16_t            archive_comment_len;
} ngx_unzip_end_of_central_dir_t;

typedef union {
    ngx_unzip_local_data_header_t   local_data_header;
    ngx_unzip_file_header_t         file_header;
    ngx_unzip_digital_sig_t         digital_sig;
    ngx_unzip_end_of_central_dir_t  end_of_central_dir;
    ngx_unzip_extra_data_record_t   extra_data_record;
} ngx_unzip_record_t;

typedef struct ngx_unzip_ctx_s {
    struct ngx_unzip_ctx_s *parent;

    ngx_unzip_state_e   state;
    off_t               current_field_len;
    off_t               current_field_pos;

    ngx_pool_t          *pool;
    ngx_log_t           *log;

    u_char              accumulator[sizeof(ngx_unzip_record_t)];

    u_char              *current_field;
    u_char              *current_field_ptr;

    union {
        ngx_unzip_local_data_header_t   local_data_header;
        ngx_unzip_file_header_t         file_header;
        ngx_unzip_digital_sig_t         digital_sig;
        ngx_unzip_end_of_central_dir_t  end_of_central_dir;
        ngx_unzip_extra_data_record_t   extra_data_record;
    };

    ngx_str_t           archive_name;
    ngx_str_t           file_name;

    ngx_str_t           prev_elm, current_elm;
    ngx_str_t           prev_archive_path, current_archive_path;
    ngx_int_t           entry_no;

    void                *preallocated;
    char                *free_mem;
    ngx_uint_t          allocated;

    z_stream            stream;

    ngx_buf_t           *output_buffer;
    ngx_chain_t         *output_chain;
    ngx_chain_t         *buf_pool;

    ngx_http_upload_ctx_t       *upload_ctx;
    ngx_upload_field_filter_t   *next_field_filter; 
    ngx_upload_content_filter_t *next_content_filter; 
    ngx_unzip_decompression_method_t *decompression_method;

    uint32_t            calculated_crc32;

    unsigned int        discard_data:1;
} ngx_unzip_ctx_t;

static void *ngx_http_unzip_filter_alloc(void *opaque, u_int items,
    u_int size);
static void ngx_http_unzip_filter_free(void *opaque, void *address);
static void ngx_http_unzip_error(ngx_unzip_ctx_t *ctx);
void ngx_http_unzip_split_chain(ngx_chain_t *cl, off_t *limit, ngx_buf_t *buf, ngx_chain_t *newcl);
ngx_int_t
ngx_http_unzip_chain_copy_range(ngx_chain_t *chain, ngx_chain_t **copy, off_t *limit,
    ngx_pool_t *pool, ngx_chain_t **free);
void ngx_http_unzip_reclaim_chain(ngx_chain_t *cl, ngx_chain_t **free);
void ngx_http_unzip_chain_advance(ngx_chain_t *chain, ngx_chain_t *copy);

static char * ngx_upload_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_upload_unzip_create_loc_conf(ngx_conf_t *cf);
static char *ngx_upload_unzip_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static ngx_int_t ngx_http_unzip_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u);
static ngx_int_t ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u,
    ngx_chain_t *chain);

static ngx_int_t ngx_http_unzip_extract_start(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_extract_finish(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_extract_abort(ngx_unzip_ctx_t *ctx);
static ngx_int_t ngx_http_unzip_extract_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain);

static ngx_int_t ngx_http_unzip_inflate_start(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_inflate_finish(ngx_unzip_ctx_t *ctx);
static void ngx_http_unzip_inflate_abort(ngx_unzip_ctx_t *ctx);
static ngx_int_t ngx_http_unzip_inflate_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain);

static char *ngx_http_unzip_window(ngx_conf_t *cf, void *post, void *data);
static char *ngx_http_unzip_hash(ngx_conf_t *cf, void *post, void *data);

static ngx_int_t
ngx_http_unzip_set_decompression_method(ngx_unzip_ctx_t *ctx, uint16_t compression_method_number);
static ngx_int_t ngx_http_unzip_parse_file_name(ngx_unzip_ctx_t *ctx, ngx_str_t *file_name);

static ngx_unzip_decompression_method_t /* {{{ */
ngx_unzip_decompression_methods[] = {

    { ZIP_METHOD_STORED,
      ngx_http_unzip_extract_start,
      ngx_http_unzip_extract_finish,
      ngx_http_unzip_extract_abort,
      ngx_http_unzip_extract_process_chain },

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
static ngx_conf_post_handler_pt  ngx_http_unzip_hash_p = ngx_http_unzip_hash;

static ngx_command_t  ngx_upload_unzip_filter_commands[] = { /* {{{ */

    /*
     * Enables unzipping of uploaded file
     */
    { ngx_string("upload_unzip"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_upload_unzip_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies size and number of buffers to use for decompressing
     */
    { ngx_string("upload_unzip_buffers"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_loc_conf_t, bufs),
      NULL },

    /*
     * Specifies window size to use for decompressing
     */
    { ngx_string("upload_unzip_window"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_loc_conf_t, wbits),
      &ngx_http_unzip_window_p },

    { ngx_string("upload_unzip_hash"), 
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,  
      offsetof(ngx_unzip_loc_conf_t, memlevel),
      &ngx_http_unzip_hash_p },

    /*
     * Specifies maximal allowed length of file in ZIP archive
     */
    { ngx_string("upload_unzip_max_file_name_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_loc_conf_t, max_file_name_len),
      NULL },

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_upload_unzip_filter_module_ctx = { /* {{{ */
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_upload_unzip_create_loc_conf,      /* create location configuration */
    ngx_upload_unzip_merge_loc_conf        /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_upload_unzip_filter_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_upload_unzip_filter_module_ctx,   /* module context */
    ngx_upload_unzip_filter_commands,      /* module directives */
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

static char * /* {{{ ngx_upload_unzip_command */
ngx_upload_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf;

    ulcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upload_module);

    if(ngx_http_upload_add_filter(ulcf, &ngx_http_unzip_content_filter, cf->pool) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_process_chain */
ngx_http_unzip_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain) {
    ngx_int_t result;
    ngx_buf_t *buf;
    ngx_unzip_loc_conf_t *uzcf;

    uzcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_upload_unzip_filter_module); 

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
                            case EXTRA_DATA_RECORD_SIGNATURE:
                                ctx->state = unzip_state_extra_data_record;
                                break;
                            case CENTRAL_FILE_HEADER_SIGNATURE:
                                ctx->state = unzip_state_file_header;
                                break;
                            case END_OF_CENTRAL_DIR_SIGNATURE:
                                ctx->state = unzip_state_central_directory_end;
                                break;
                            case DIGITAL_SIGNATURE_HEADER_SIGNATURE:
                                ctx->state = unzip_state_digital_sig_header;
                                break;
                            default:
                                ngx_log_error(NGX_LOG_ALERT, ctx->log, 0
                                    , "unknown signature in ZIP file: %uxD"
                                    , (uint32_t)EXTRACT_LONG(ctx->current_field)
                                    );
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

                        ctx->local_data_header.version_needed = EXTRACT_SHORT(ctx->current_field);
                        ctx->local_data_header.flags = EXTRACT_SHORT(ctx->current_field + 2);
                        ctx->local_data_header.compression_method = EXTRACT_SHORT(ctx->current_field + 4);
                        ctx->local_data_header.last_mod_time = EXTRACT_SHORT(ctx->current_field + 6);
                        ctx->local_data_header.last_mod_date = EXTRACT_SHORT(ctx->current_field + 8);
                        ctx->local_data_header.crc32 = EXTRACT_LONG(ctx->current_field + 10);
                        ctx->local_data_header.compressed_size = EXTRACT_LONG(ctx->current_field + 14);
                        ctx->local_data_header.uncompressed_size = EXTRACT_LONG(ctx->current_field + 18);

                        ctx->local_data_header.file_name_len = EXTRACT_SHORT(ctx->current_field + 22);
                        ctx->local_data_header.extra_field_len = EXTRACT_SHORT(ctx->current_field + 24);

                        if(uzcf->max_file_name_len > 0 &&
                            ctx->local_data_header.file_name_len > uzcf->max_file_name_len)
                        {
                            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0
                                , "file name in is too long: %u"
                                , ctx->local_data_header.file_name_len
                                );
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ngx_http_unzip_set_decompression_method(ctx,
                            ctx->local_data_header.compression_method) != NGX_OK) 
                        {
                            return NGX_UNZIP_MALFORMED;
                        } 

                        if(ctx->local_data_header.version_needed > ZIP_VERSION)
                        {
                            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0
                                , "more recent version of unzip implementation required: %u, have %u"
                                , ctx->local_data_header.version_needed, ZIP_VERSION
                                );
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ctx->local_data_header.flags
                            & (ZIP_FLAG_ENCRYPTED|ZIP_FLAG_STRONG_ENCRYPTION|ZIP_FLAG_LOCAL_HEADER_OBFUSCATED))
                        {
                            ngx_log_error(NGX_LOG_INFO, ctx->log, 0
                                , "skipping encrypted ZIP file"
                                );
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ctx->local_data_header.file_name_len > 0)
                            ctx->state = unzip_state_file_name;
                        else if(ctx->local_data_header.extra_field_len > 0)
                            ctx->state = unzip_state_extra_field;
                        else if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->local_data_header.compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break; /* }}} */
                case unzip_state_file_name: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->file_name.len = ctx->local_data_header.file_name_len;

                        ctx->file_name.data = ngx_palloc(ctx->pool, ctx->file_name.len);

                        if(ctx->file_name.data == NULL) {
                            return NGX_UPLOAD_NOMEM;
                        }

                        ctx->current_field_len = ctx->local_data_header.file_name_len;
                        ctx->current_field_ptr = ctx->current_field = ctx->file_name.data;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ngx_http_unzip_parse_file_name(ctx, &ctx->file_name) != NGX_OK) {
                            return NGX_UNZIP_MALFORMED;
                        }

                        if(ctx->local_data_header.extra_field_len > 0)
                            ctx->state = unzip_state_extra_field;
                        else if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->local_data_header.compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break; /* }}} */
                case unzip_state_extra_field:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->local_data_header.extra_field_len;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_unlimited_file_data;
                        else if(ctx->local_data_header.compressed_size > 0)
                            ctx->state = unzip_state_file_data;
                        else if(ctx->local_data_header.flags & ZIP_FLAG_UNLIMITED)
                            ctx->state = unzip_state_data_descriptor;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_file_data: /* {{{ */
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->local_data_header.compressed_size;

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

                        ctx->local_data_header.crc32 = EXTRACT_LONG(ctx->current_field);
                        ctx->local_data_header.compressed_size = EXTRACT_LONG(ctx->current_field + 4);
                        ctx->local_data_header.uncompressed_size = EXTRACT_LONG(ctx->current_field + 8);

                        ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_extra_data_record:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = EXTRA_DATA_RECORD_LEN - SIGNATURE_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    *ctx->current_field_ptr++ = *buf->pos;
                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        ctx->extra_data_record.extra_field_len = EXTRACT_LONG(ctx->current_field);

                        if(ctx->extra_data_record.extra_field_len > 0)
                            ctx->state = unzip_state_extra_data_record_data;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_extra_data_record_data:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->extra_data_record.extra_field_len;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;
                        ctx->state = unzip_state_signature;
                    }
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

                        ctx->file_header.version_made_by = EXTRACT_SHORT(ctx->current_field);
                        ctx->file_header.version_needed = EXTRACT_SHORT(ctx->current_field + 2);
                        ctx->file_header.flags = EXTRACT_SHORT(ctx->current_field + 4);
                        ctx->file_header.compression_method = EXTRACT_SHORT(ctx->current_field + 6);
                        ctx->file_header.last_mod_time = EXTRACT_SHORT(ctx->current_field + 8);
                        ctx->file_header.last_mod_date = EXTRACT_SHORT(ctx->current_field + 10);
                        ctx->file_header.crc32 = EXTRACT_LONG(ctx->current_field + 12);
                        ctx->file_header.compressed_size = EXTRACT_LONG(ctx->current_field + 16);
                        ctx->file_header.uncompressed_size = EXTRACT_LONG(ctx->current_field + 20);

                        ctx->file_header.file_name_len = EXTRACT_SHORT(ctx->current_field + 24);
                        ctx->file_header.extra_field_len = EXTRACT_SHORT(ctx->current_field + 26);
                        ctx->file_header.file_comment_len = EXTRACT_SHORT(ctx->current_field + 38);

                        ctx->file_header.disk_number_start = EXTRACT_SHORT(ctx->current_field + 40);
                        ctx->file_header.internal_file_attrs = EXTRACT_SHORT(ctx->current_field + 42);
                        ctx->file_header.external_file_attrs = EXTRACT_LONG(ctx->current_field + 46);
                        ctx->file_header.relative_offset = EXTRACT_LONG(ctx->current_field + 50);

                        if(ctx->file_header.file_name_len > 0)
                            ctx->state = unzip_state_file_header_file_name;
                        else if(ctx->file_header.extra_field_len > 0)
                            ctx->state = unzip_state_file_header_extra_field;
                        else if(ctx->file_header.file_comment_len > 0)
                            ctx->state = unzip_state_file_header_file_comment;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_file_header_file_name:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->file_header.file_name_len;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ctx->file_header.extra_field_len > 0)
                            ctx->state = unzip_state_file_header_extra_field;
                        else if(ctx->file_header.file_comment_len > 0)
                            ctx->state = unzip_state_file_header_file_comment;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_file_header_extra_field:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->file_header.extra_field_len;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        if(ctx->file_header.file_comment_len > 0)
                            ctx->state = unzip_state_file_header_file_comment;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_file_header_file_comment:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->file_header.extra_field_len;

                        ctx->next_field_filter->start(ctx->upload_ctx);
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;
                        ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_digital_sig_header:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = DIGITAL_SIGNATURE_HEADER_LEN;
                        ctx->current_field_ptr = ctx->current_field = ctx->accumulator;
                    }

                    ctx->current_field_pos++;
                    *ctx->current_field_ptr++ = *buf->pos;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;

                        ctx->digital_sig.data_size = EXTRACT_LONG(ctx->current_field);

                        if(ctx->digital_sig.data_size > 0)
                            ctx->state = unzip_state_digital_sig;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_digital_sig:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->digital_sig.data_size;
                    }

                    ctx->current_field_pos++;
                    
                    if(ctx->current_field_pos == ctx->current_field_len) {
                        ctx->current_field_pos = 0;
                        ctx->state = unzip_state_signature;
                    }
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

                        ctx->end_of_central_dir.disk_number = EXTRACT_SHORT(ctx->current_field);
                        ctx->end_of_central_dir.number_of_disk_with_start_of_dir = EXTRACT_SHORT(ctx->current_field + 2);
                        ctx->end_of_central_dir.number_of_entries_on_this_disk = EXTRACT_SHORT(ctx->current_field + 4);
                        ctx->end_of_central_dir.total_number_of_entries = EXTRACT_SHORT(ctx->current_field + 6);
                        ctx->end_of_central_dir.size_of_directory = EXTRACT_LONG(ctx->current_field + 8);
                        ctx->end_of_central_dir.offset_of_start = EXTRACT_LONG(ctx->current_field + 12);
                        ctx->end_of_central_dir.archive_comment_len = EXTRACT_SHORT(ctx->current_field + 16);

                        if(ctx->end_of_central_dir.archive_comment_len > 0)
                            ctx->state = unzip_state_archive_comment;
                        else
                            ctx->state = unzip_state_signature;
                    }
                    break;
                case unzip_state_archive_comment:
                    if(ctx->current_field_pos == 0) {
                        ctx->current_field_len = ctx->end_of_central_dir.archive_comment_len;

                        ctx->next_field_filter->start(ctx->upload_ctx);
                    }

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
    ngx_unzip_loc_conf_t           *uzcf;
    ngx_unzip_ctx_t            *ctx, *parent;
    ngx_http_upload_loc_conf_t *ulcf;

    uzcf = ngx_http_get_module_loc_conf(u->request, ngx_upload_unzip_filter_module);
    ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

    ctx = ngx_http_get_module_ctx(u->request, ngx_upload_unzip_filter_module);

    parent = ctx;

    if(ctx == NULL) {
        ctx = ngx_pcalloc(u->request->pool, sizeof(ngx_unzip_ctx_t));
        if (ctx == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        ctx->buf_pool = NULL;
        ctx->preallocated = NULL;
    }

    ctx->parent = parent;

    ngx_http_set_ctx(u->request, ctx, ngx_upload_unzip_filter_module);

    ctx->state = unzip_state_signature;
    ctx->upload_ctx = u;

    ctx->pool = u->request->pool; 
    ctx->log = u->log; 

    ctx->next_field_filter = ngx_upload_get_next_field_filter(u);
    ctx->next_content_filter = ngx_upload_get_next_content_filter(u);

    ngx_upload_get_archive_elm(u, &ctx->prev_elm);

    ngx_upload_get_archive_path(u, &ctx->prev_archive_path);

    ngx_upload_get_file_name(u, &ctx->archive_name);

    ctx->entry_no = 0;

    ctx->current_elm.len = ctx->prev_elm.len + ulcf->archive_elm_separator.len + NGX_OFF_T_LEN;
    ctx->current_elm.data = ngx_palloc(ctx->pool, ctx->current_elm.len);

    if(ctx->current_elm.data == NULL)
        return NGX_UPLOAD_NOMEM;

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_unzip_finish_handler */
ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_upload_unzip_filter_module);

    if (ctx->state == unzip_state_file_data) {
        if(!ctx->discard_data)
            ctx->decompression_method->abort(ctx);
    }

    ngx_upload_set_archive_elm(u, &ctx->prev_elm);

    ngx_upload_set_archive_path(u, &ctx->prev_archive_path);

    ngx_http_set_ctx(u->request, ctx->parent, ngx_upload_unzip_filter_module);
} /* }}} */

static void /* {{{ ngx_http_unzip_abort_handler */
ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_upload_unzip_filter_module);

    if (ctx->state == unzip_state_file_data) {
        if(!ctx->discard_data)
            ctx->decompression_method->abort(ctx);
    }

    ngx_upload_set_archive_elm(u, &ctx->prev_elm);

    ngx_upload_set_archive_path(u, &ctx->prev_archive_path);

    ngx_http_set_ctx(u->request, ctx->parent, ngx_upload_unzip_filter_module);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_data_handler */
ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u, ngx_chain_t *chain) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_upload_unzip_filter_module);

    return ngx_http_unzip_process_chain(ctx, chain);
} /* }}} */

static void * /* {{{ ngx_upload_unzip_create_loc_conf */
ngx_upload_unzip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_unzip_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_unzip_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->wbits = NGX_CONF_UNSET_SIZE;
    conf->memlevel = NGX_CONF_UNSET_SIZE;
    conf->max_file_name_len = NGX_CONF_UNSET_SIZE;

    /*
     * conf->bufs
     * zeroed by ngx_pcalloc
     */

    return conf;
} /* }}} */

static char * /* {{{ ngx_upload_unzip_merge_loc_conf */
ngx_upload_unzip_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_unzip_loc_conf_t  *prev = parent;
    ngx_unzip_loc_conf_t  *conf = child;

    ngx_conf_merge_bufs_value(conf->bufs, prev->bufs, 4, ngx_pagesize);

    ngx_conf_merge_size_value(conf->wbits, prev->wbits, MAX_WBITS);
    ngx_conf_merge_size_value(conf->memlevel, prev->memlevel,
                              MAX_MEM_LEVEL - 1);

    ngx_conf_merge_size_value(conf->max_file_name_len,
                              prev->max_file_name_len,
                              (size_t) 512);

    return NGX_CONF_OK;
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

static char * /* {{{ ngx_http_unzip_hash */
ngx_http_unzip_hash(ngx_conf_t *cf, void *post, void *data)
{   
    int *np = data;

    int  memlevel, hsize;

    memlevel = 9;

    for (hsize = 128 * 1024; hsize > 256; hsize >>= 1) {

        if (hsize == *np) {
            *np = memlevel;

            return NGX_CONF_OK; 
        }

        memlevel--;
    }

    return "must be 512, 1k, 2k, 4k, 8k, 16k, 32k, 64k, or 128k";
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
    ngx_unzip_loc_conf_t           *uzcf;
    int                            wbits, memlevel;

    ctx->stream.zalloc = ngx_http_unzip_filter_alloc;
    ctx->stream.zfree = ngx_http_unzip_filter_free;
    ctx->stream.opaque = ctx;
    ctx->stream.avail_in = 0;
    ctx->stream.next_in = Z_NULL;

    uzcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_upload_unzip_filter_module); 

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

    if (ctx->preallocated == NULL) {
        wbits = uzcf->wbits;
        memlevel = MAX_MEM_LEVEL - 1; //uzcf->memlevel;

        if (ctx->local_data_header.uncompressed_size > 0) {

            /* the actual zlib window size is smaller by 262 bytes */

            while ((off_t)ctx->local_data_header.uncompressed_size < ((1 << (wbits - 1)) - 262)) {
                wbits--;
                memlevel--;
            }
        }

        /*
         * We preallocate a memory for zlib in one buffer (200K-400K), this
         * decreases a number of malloc() and free() calls and also probably
         * decreases a number of syscalls (sbrk() and so on).
         * Besides we free this memory as soon as the gzipping will complete
         * and do not wait while a whole response will be sent to a client.
         *
         * 8K is for zlib deflate_state, it takes
         *  *) 5816 bytes on i386 and sparc64 (32-bit mode)
         *  *) 5920 bytes on amd64 and sparc64
         */

        ctx->allocated = 8192 + (1 << (wbits + 2)) + (1 << (memlevel + 9));

        ctx->preallocated = ngx_palloc(ctx->pool, ctx->allocated);
        if (ctx->preallocated == NULL) {
            return NGX_ERROR;
        }

        ctx->free_mem = ctx->preallocated;
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

    ctx->allocated += (ctx->free_mem - (char*)ctx->preallocated);
    ctx->free_mem = ctx->preallocated;

    if(ctx->next_content_filter->finish)
        ctx->next_content_filter->finish(ctx->upload_ctx);

    inflateEnd(&ctx->stream);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "finished inflating file \"%V\"", &ctx->file_name);
} /* }}} */

static void /* {{{ ngx_http_unzip_inflate_abort */
ngx_http_unzip_inflate_abort(ngx_unzip_ctx_t *ctx) {
    ctx->allocated += ctx->free_mem - (char*)ctx->preallocated;
    ctx->free_mem = ctx->preallocated;

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
    int flush;

    while(chain != NULL && !chain->buf->last_in_chain) {
        remaining = chain->buf->last - chain->buf->pos;

        if(ctx->current_field_len - ctx->current_field_pos > remaining) {
            ctx->stream.avail_in = remaining;
            flush = Z_NO_FLUSH;
        }else{
            ctx->stream.avail_in = ctx->current_field_len - ctx->current_field_pos;
            flush = Z_SYNC_FLUSH;
        }

        ctx->stream.next_in = chain->buf->pos;

        do{
            ctx->stream.avail_out = ctx->output_buffer->end - ctx->output_buffer->start;
            ctx->stream.next_out = ctx->output_buffer->pos = ctx->output_buffer->start;

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "inflate in: ai:%ud ni:%p ao:%ud no:%p fl:%d",
                           ctx->stream.avail_in, ctx->stream.next_in,
                           ctx->stream.avail_out, ctx->stream.next_out,
                           flush
                          );

            rc = inflate(&ctx->stream, flush);

            ngx_log_debug5(NGX_LOG_DEBUG_HTTP, ctx->log, 0,
                           "inflate out: ai:%ud ni:%p ao:%ud no:%p rc:%d",
                           ctx->stream.avail_in, ctx->stream.next_in,
                           ctx->stream.avail_out, ctx->stream.next_out,
                           rc
                          );

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
        }while(ctx->stream.avail_out == 0 && ctx->stream.avail_in > 0 && rc == Z_OK);

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

static ngx_int_t /* {{{ ngx_http_unzip_extract_start */
ngx_http_unzip_extract_start(ngx_unzip_ctx_t *ctx) {
    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "started extracting file \"%V\"", &ctx->file_name);

    if(ctx->next_content_filter->start)
        return ctx->next_content_filter->start(ctx->upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_unzip_extract_finish */
ngx_http_unzip_extract_finish(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->finish)
        ctx->next_content_filter->finish(ctx->upload_ctx);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "finished extracting file \"%V\"", &ctx->file_name);
} /* }}} */

static void /* {{{ ngx_http_unzip_extract_abort */
ngx_http_unzip_extract_abort(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->abort)
        ctx->next_content_filter->abort(ctx->upload_ctx);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "aborted extracting file \"%V\"", &ctx->file_name);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_extract_process_chain */
ngx_http_unzip_extract_process_chain(ngx_unzip_ctx_t *ctx, ngx_chain_t *chain) {
    ngx_chain_t *copy;
    off_t limit = ctx->current_field_len - ctx->current_field_pos;
    ngx_int_t rc;

    if(ctx->next_content_filter->process_chain) {
        rc = ngx_http_unzip_chain_copy_range(chain, &copy, &limit, ctx->pool, &ctx->buf_pool);

        if(rc != NGX_OK) {
            return rc;
        }

        ctx->current_field_pos = ctx->current_field_len - limit;

        rc = ctx->next_content_filter->process_chain(ctx->upload_ctx, copy); 

        ngx_http_unzip_chain_advance(chain, copy);

        ngx_http_unzip_reclaim_chain(copy, &ctx->buf_pool);

        return rc;
    }else
        return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_unzip_set_archive_elm */
ngx_http_unzip_set_archive_elm(ngx_unzip_ctx_t *ctx, off_t elm_id) {
    ngx_http_upload_loc_conf_t *ulcf;

    ulcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_http_upload_module);

    ctx->current_elm.len = ngx_sprintf(ctx->current_elm.data, "%V%V%O", &ctx->prev_elm, &ulcf->archive_elm_separator, elm_id) - ctx->current_elm.data;

    ngx_upload_set_archive_elm(ctx->upload_ctx, &ctx->current_elm);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_unzip_set_archive_path */
ngx_http_unzip_set_archive_path(ngx_unzip_ctx_t *ctx, ngx_str_t *file_name, ngx_str_t *path) {
    ngx_http_upload_loc_conf_t *ulcf;

    ulcf = ngx_http_get_module_loc_conf(ctx->upload_ctx->request, ngx_http_upload_module);

    ctx->current_archive_path.len = ctx->prev_archive_path.len + file_name->len + ulcf->archive_path_separator.len + path->len;

    ctx->current_archive_path.data = ngx_palloc(ctx->pool, ctx->current_archive_path.len);

    if(ctx->current_archive_path.data == NULL)
        return NGX_UPLOAD_NOMEM;

    ctx->current_archive_path.len = ngx_sprintf(ctx->current_archive_path.data, "%V%V%V%V", &ctx->prev_archive_path, file_name, &ulcf->archive_path_separator, path) - ctx->current_archive_path.data;

    ngx_upload_set_archive_path(ctx->upload_ctx, &ctx->current_archive_path);

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
    ngx_upload_set_file_name(ctx->upload_ctx, &element_name);

    rc = ngx_upload_set_exten(ctx->upload_ctx, &element_name, &exten);

    if(rc != NGX_OK) {
        return rc;
    }

    rc = ngx_upload_resolve_content_type(ctx->upload_ctx, &exten, &content_type);

    if(rc != NGX_OK) {
        return rc;
    }

    ngx_upload_set_content_type(ctx->upload_ctx, &content_type);

    rc = ngx_http_unzip_set_archive_path(ctx, &ctx->archive_name, &archive_path);

    if(rc != NGX_OK) {
        return rc;
    }

    ngx_http_unzip_set_archive_elm(ctx, ctx->entry_no++);

    return NGX_OK;
} /* }}} */

static void * /* {{{ ngx_http_unzip_filter_alloc */
ngx_http_unzip_filter_alloc(void *opaque, u_int items, u_int size)
{
    ngx_unzip_ctx_t *ctx = opaque;

    void        *p;
    ngx_uint_t   alloc;

    alloc = items * size;

    if (alloc % 512 != 0) {

        /*
         * The zlib deflate_state allocation, it takes about 6K,
         * we allocate 8K.  Other allocations are divisible by 512.
         */

        alloc = (alloc + ngx_pagesize - 1) & ~(ngx_pagesize - 1);
    }

    if (alloc <= ctx->allocated) {
        p = ctx->free_mem;
        ctx->free_mem += alloc;
        ctx->allocated -= alloc;

        ngx_log_debug4(NGX_LOG_DEBUG_HTTP, ctx->upload_ctx->request->connection->log, 0,
                       "unzip alloc: n:%ud s:%ud a:%ud p:%p",
                       items, size, alloc, p);

        return p;
    }

    ngx_log_error(NGX_LOG_ALERT, ctx->upload_ctx->request->connection->log, 0,
                  "unzip filter failed to use preallocated memory: %ud of %ud",
                  items * size, ctx->allocated);
    p = ngx_palloc(ctx->pool, items * size);

    return p;
} /* }}} */

static void /* {{{ ngx_http_unzip_filter_free */
ngx_http_unzip_filter_free(void *opaque, void *address)
{
} /* }}} */

ngx_int_t /* {{{ ngx_http_unzip_chain_copy_range */
ngx_http_unzip_chain_copy_range(ngx_chain_t *chain, ngx_chain_t **copy, off_t *limit, ngx_pool_t *pool, ngx_chain_t **free) {
    ngx_chain_t *cl, *last, *r, *new;
    ngx_buf_t *buf;

    if(chain == NULL || *limit == 0) {
        *copy = NULL;
        return NGX_OK;
    }

    last = r = NULL;

    for(cl = chain; cl; cl = cl->next) {
        if(*free == NULL) {
            buf = ngx_palloc(pool, sizeof(ngx_buf_t));

            if (buf == NULL) {
                return NGX_UPLOAD_NOMEM;
            }

            *free = ngx_palloc(pool, sizeof(ngx_chain_t));

            if (buf == NULL) {
                return NGX_UPLOAD_NOMEM;
            }

            (*free)->buf = buf;
            (*free)->next = NULL;
        }

        new = *free;
        *free = (*free)->next;

        ngx_memcpy(new->buf, cl->buf, sizeof(ngx_buf_t));

        new->next = NULL;

        if(last == NULL) {
            r = new;
            last = new;
        }else{
            last->next = new;
            last = new; 
        }

        if(cl->buf->last - cl->buf->pos > *limit) {
            new->buf->last = new->buf->pos + *limit; 

            *limit -= cl->buf->last - cl->buf->pos; 

            break;
        }

        *limit -= cl->buf->last - cl->buf->pos; 
    }

    *copy = r;
    return NGX_OK;
} /* }}} */

void /* {{{ ngx_http_unzip_reclaim_chain */
ngx_http_unzip_reclaim_chain(ngx_chain_t *cl, ngx_chain_t **free) {
    ngx_chain_t *next;

    while(cl) {
        next = cl->next;

        if(*free == NULL) {
            *free = cl;
            cl->next = NULL;
        }else{
            cl->next = *free;
            *free = cl;
        }

        cl = next;
    }
} /* }}} */

void /* {{{ ngx_http_unzip_chain_advance */
ngx_http_unzip_chain_advance(ngx_chain_t *chain, ngx_chain_t *copy) {
    ngx_chain_t *c1 = chain, *c2 = copy;

    while(c2) {
        if(c1 == NULL) {
            break;
        }

        c1->buf->pos = c2->buf->last;

        c1 = c1->next;
        c2 = c2->next;
    }
} /* }}} */

