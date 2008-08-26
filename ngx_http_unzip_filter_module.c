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
#define SIGNATURE_LEN                       4 
#define LOCAL_DATA_HEADER_LEN               30
#define FILE_HEADER_LEN                     46
#define DATA_DESCRIPTOR_LEN                 12

#define ZIP_METHOD_STORED                   0
#define ZIP_METHOD_DEFLATED                 8

#define ZIP_FLAG_HAVE_DATA_DESC             0x0008

#define ZIP_VERSION                         20

#if (NGX_HAVE_LITTLE_ENDIAN && NGX_HAVE_NONALIGNED)
#define EXTRACT_SHORT(x) (uint16_t)(*(x) | *((x)+1) << 8)
#define EXTRACT_LONG(x) (uint32_t)(*(x) | *((x)+1) << 8 | *((x)+2) << 16 | *((x)+3) << 24)
#else
#define EXTRACT_SHORT(x) (uint16_t)(*(x) << 8 | *((x)+1))
#define EXTRACT_LONG(x) (uint32_t)(*(x) << 24 | *((x)+1) << 16 | *((x)+2) << 8 | *((x)+3))
#endif

typedef struct {
    ngx_bufs_t           bufs;
    unsigned int         recursive:1;
} ngx_unzip_conf_t;

typedef enum {
    unzip_state_signature,
    unzip_state_local_data_header,
    unzip_state_file_name,
    unzip_state_extra_field,
    unzip_state_file_data,
    unzip_state_data_descriptor,
    unzip_state_decryption_header,
    unzip_state_extra_data_record,
    unzip_state_file_header,
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
    ngx_unzip_state_e   state;
    size_t              current_field_len;
    size_t              current_field_pos;

    ngx_pool_t          *pool;
    ngx_log_t           *log;

    u_char              buffer[512];

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

    ngx_http_upload_ctx_t       *upload_ctx;
    ngx_upload_content_filter_t *next_content_filter; 

    unsigned int        discard_data:1;
} ngx_unzip_ctx_t;

static char * ngx_http_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void *ngx_http_unzip_create_loc_conf(ngx_conf_t *cf);

static ngx_int_t ngx_http_unzip_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u);
static ngx_int_t ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u,
    u_char *buf, size_t len);

static ngx_upload_content_filter_t ngx_unzip_content_filter = {
    ngx_http_unzip_start_handler,
    ngx_http_unzip_finish_handler,
    ngx_http_unzip_abort_handler,
    ngx_http_unzip_data_handler
};

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
     * Specifies size and numbers of buffers to use for decompressing
     */
    { ngx_string("unzip_buffers"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_bufs_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_unzip_conf_t, bufs),
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

u_char unzip_buffer[4096];

static char * /* {{{ ngx_http_unzip_command */
ngx_http_unzip_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_unzip_conf_t           *uzcf = conf;
    ngx_http_upload_loc_conf_t *ulcf;

    ngx_str_t                   *value;

    unsigned int                on = 0;

    ulcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upload_module);

    value = cf->args->elts;

    if(ngx_strcmp(value[1].data, "on") == 0) {
        on = 1;
        uzcf->recursive = 0;
    }

    if(ngx_strcmp(value[1].data, "recursive") == 0) {
        on = 1;
        uzcf->recursive = 1;
    }

    if(on) {
        if(ngx_http_upload_add_filter(ulcf, &ngx_unzip_content_filter, cf->pool) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t
ngx_unzip_decompress_start(ngx_unzip_ctx_t *ctx) {
    ngx_int_t rc;

    ctx->stream.zalloc = Z_NULL;
    ctx->stream.zfree = Z_NULL;
    ctx->stream.opaque = Z_NULL;
    ctx->stream.avail_in = 0;
    ctx->stream.next_in = Z_NULL;

    rc = inflateInit2(&ctx->stream, -15);

    if (rc != Z_OK) {
        ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
              "inflateInit() failed: %d", rc);
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "started unzipping file \"%V\"", &ctx->file_name);

    rc = ngx_upload_set_file_name(ctx->upload_ctx, &ctx->file_name);

    if(rc != NGX_OK) {
        goto cleanup;
    }

    if(ctx->next_content_filter->start) {
        rc = ctx->next_content_filter->start(ctx->upload_ctx);

        if(rc != NGX_OK) {
            goto cleanup;
        }

        return rc;
    }

    return NGX_OK;
cleanup:
    inflateEnd(&ctx->stream);    
    return rc;
}

static void
ngx_unzip_decompress_finish(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->finish)
        ctx->next_content_filter->finish(ctx->upload_ctx);

    inflateEnd(&ctx->stream);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "finished unzipping file \"%V\"", &ctx->file_name);
}

static void
ngx_unzip_decompress_abort(ngx_unzip_ctx_t *ctx) {
    if(ctx->next_content_filter->abort)
        ctx->next_content_filter->abort(ctx->upload_ctx);

    inflateEnd(&ctx->stream);

    ngx_log_error(NGX_LOG_INFO, ctx->log, 0,
          "aborted unzipping file \"%V\"", &ctx->file_name);
}

static ngx_int_t
ngx_unzip_decompress_data(ngx_unzip_ctx_t *ctx, u_char *start, u_char *end) {
    int rc;
    size_t remaining = end - start;

    if(ctx->current_field_len - ctx->current_field_pos > remaining)
        ctx->stream.avail_in = remaining;
    else
        ctx->stream.avail_in = ctx->current_field_len - ctx->current_field_pos;

    ctx->stream.next_in = start;

    do{
        ctx->stream.avail_out = sizeof(unzip_buffer);
        ctx->stream.next_out = unzip_buffer;

        rc = inflate(&ctx->stream, Z_NO_FLUSH);

        if(rc == Z_OK || rc == Z_STREAM_END) {
            if(ctx->next_content_filter->process_buf)
                ctx->next_content_filter->process_buf(ctx->upload_ctx, 
                    unzip_buffer, sizeof(unzip_buffer) - ctx->stream.avail_out);
        }

        if(rc == Z_STREAM_END) {
            return ctx->stream.next_in - start;
        }

        if (rc != Z_OK) {
            ngx_log_error(NGX_LOG_ALERT, ctx->log, 0,
                  "inflate() failed: %d", rc);
            return NGX_ERROR;
        }
    }while(ctx->stream.avail_out == 0);

    return ctx->stream.next_in - start;
}

static ngx_int_t
unzip_process_buf(ngx_unzip_ctx_t *ctx, u_char *start, u_char *end) {
    ngx_int_t result;
    u_char *p;

    for(p = start ; p != end ; p++) {
        switch(ctx->state) {
            case unzip_state_signature:
                if(ctx->current_field_pos == 0) {
                    ctx->current_field_len = SIGNATURE_LEN;
                    ctx->current_field_ptr = ctx->current_field = ctx->buffer;
                }

                *ctx->current_field_ptr++ = *p;
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
                        default:
                            return NGX_UNZIP_MALFORMED;
                    }
                }
                break;
            case unzip_state_local_data_header:
                if(ctx->current_field_pos == 0) {
                    ctx->current_field_len = LOCAL_DATA_HEADER_LEN - SIGNATURE_LEN;
                    ctx->current_field_ptr = ctx->current_field = ctx->buffer;

                    ctx->discard_data = 0;
                }

                *ctx->current_field_ptr++ = *p;
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

                    if(ctx->compression_method != ZIP_METHOD_STORED &&
                        ctx->compression_method != ZIP_METHOD_DEFLATED)
                    {
                        return NGX_UNZIP_MALFORMED;
                    }

                    if(ctx->version_needed > ZIP_VERSION)
                    {
                        return NGX_UNZIP_MALFORMED;
                    }

                    if(ctx->file_name_len > 0)
                        ctx->state = unzip_state_file_name;
                    else if(ctx->extra_field_len > 0)
                        ctx->state = unzip_state_extra_field;
                    else if(ctx->compressed_size > 0)
                        ctx->state = unzip_state_file_data;
                    else if(ctx->flags & ZIP_FLAG_HAVE_DATA_DESC)
                        ctx->state = unzip_state_data_descriptor;
                    else
                        ctx->state = unzip_state_signature;
                }
                break;
            case unzip_state_file_name:
                if(ctx->current_field_pos == 0) {
                    ctx->file_name.len = ctx->file_name_len;

                    ctx->file_name.data = ngx_palloc(ctx->pool, ctx->file_name_len + 1);

                    if(ctx->file_name.data == NULL) {
                        return NGX_UPLOAD_NOMEM;
                    }

                    ctx->current_field_len = ctx->file_name_len;
                    ctx->current_field_ptr = ctx->current_field = ctx->file_name.data;
                }

                *ctx->current_field_ptr++ = *p;
                ctx->current_field_pos++;
                
                if(ctx->current_field_pos == ctx->current_field_len) {
                    ctx->current_field_pos = 0;

                    *ctx->current_field_ptr = '\0';

                    if(ctx->extra_field_len > 0)
                        ctx->state = unzip_state_extra_field;
                    else if(ctx->compressed_size > 0)
                        ctx->state = unzip_state_file_data;
                    else if(ctx->flags & ZIP_FLAG_HAVE_DATA_DESC)
                        ctx->state = unzip_state_data_descriptor;
                    else
                        ctx->state = unzip_state_signature;
                }
                break;
            case unzip_state_extra_field:
                if(ctx->current_field_pos == 0) {
                    ctx->current_field_len = ctx->extra_field_len;
                }

                ctx->current_field_pos++;
                
                if(ctx->current_field_pos == ctx->current_field_len) {
                    ctx->current_field_pos = 0;

                    if(ctx->compressed_size > 0)
                        ctx->state = unzip_state_file_data;
                    else if(ctx->flags & ZIP_FLAG_HAVE_DATA_DESC)
                        ctx->state = unzip_state_data_descriptor;
                    else
                        ctx->state = unzip_state_signature;
                }
                break;
            case unzip_state_file_data:
                if(ctx->current_field_pos == 0) {
                    ctx->current_field_len = ctx->compressed_size;

                    if(ngx_unzip_decompress_start(ctx) != NGX_OK) {
                        ctx->discard_data = 1;
                    }
                }
    
                if(!ctx->discard_data) {
                    result = ngx_unzip_decompress_data(ctx, p, end);

                    if(result < 0) {
                        ctx->discard_data = 1;

                        ngx_unzip_decompress_abort(ctx);

                        ctx->current_field_pos++;
                    }else{
                        ctx->current_field_pos += result;
                        p += (result - 1);
                    }
                }else
                    ctx->current_field_pos++;
                
                if(ctx->current_field_pos == ctx->current_field_len) {
                    if(!ctx->discard_data)
                        ngx_unzip_decompress_finish(ctx);

                    ctx->current_field_pos = 0;

                    if(ctx->flags & ZIP_FLAG_HAVE_DATA_DESC)
                        ctx->state = unzip_state_data_descriptor;
                    else
                        ctx->state = unzip_state_signature;
                }
                break;
            case unzip_state_data_descriptor:
                if(ctx->current_field_pos == 0) {
                    ctx->current_field_len = DATA_DESCRIPTOR_LEN;
                    ctx->current_field_ptr = ctx->current_field = ctx->buffer;
                }

                *ctx->current_field_ptr++ = *p;
                ctx->current_field_pos++;
                
                if(ctx->current_field_pos == ctx->current_field_len) {
                    ctx->current_field_pos = 0;
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
                    ctx->current_field_ptr = ctx->current_field = ctx->buffer;
                }

                *ctx->current_field_ptr++ = *p;
                ctx->current_field_pos++;
                
                if(ctx->current_field_pos == ctx->current_field_len) {
                    ctx->current_field_pos = 0;
                    ctx->state = unzip_state_signature;
                }
                break;
                break;
            case unzip_state_central_directory_end:
                break;
            case unzip_state_finish:
                break;
        }
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_unzip_start_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_conf_t           *uzcf;
    ngx_unzip_ctx_t            *ctx;

    uzcf = ngx_http_get_module_loc_conf(u->request, ngx_http_unzip_filter_module);

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    if (ctx == NULL) {
        ctx = ngx_pcalloc(u->request->pool, sizeof(ngx_unzip_ctx_t));
        if (ctx == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        ngx_http_set_ctx(u->request, ctx, ngx_http_unzip_filter_module);
    }

    ctx->state = unzip_state_signature;
    ctx->upload_ctx = u;
    ctx->next_content_filter = ngx_upload_get_next_content_filter(u);

    ctx->pool = u->request->pool; 
    ctx->log = u->log; 

    return NGX_OK;
}

static void
ngx_http_unzip_finish_handler(ngx_http_upload_ctx_t *u) {
}

static void
ngx_http_unzip_abort_handler(ngx_http_upload_ctx_t *u) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    if (ctx->state == unzip_state_file_data) {
        if(!ctx->discard_data)
            ngx_unzip_decompress_abort(ctx);
    }
}

static ngx_int_t
ngx_http_unzip_data_handler(ngx_http_upload_ctx_t *u, u_char *buf, size_t len) {
    ngx_unzip_ctx_t            *ctx;

    ctx = ngx_http_get_module_ctx(u->request, ngx_http_unzip_filter_module);

    return unzip_process_buf(ctx, buf, buf + len);
}

static void *
ngx_http_unzip_create_loc_conf(ngx_conf_t *cf)
{
    ngx_unzip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_unzip_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    /*
     * conf->bufs,
     * zeroed by ngx_pcalloc
     */

    return conf;
}

