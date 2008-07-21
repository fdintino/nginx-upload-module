/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 * Client body reception code Copyright (c) 2002-2007 Igor Sysoev
 * Temporary file name generation code Copyright (c) 2002-2007 Igor Sysoev
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define MULTIPART_FORM_DATA_STRING              "multipart/form-data"
#define BOUNDARY_STRING                         "boundary="
#define CONTENT_DISPOSITION_STRING              "Content-Disposition:"
#define CONTENT_TYPE_STRING                     "Content-Type:"
#define FORM_DATA_STRING                        "form-data"
#define ATTACHMENT_STRING                       "attachment"
#define FILENAME_STRING                         "filename=\""
#define FIELDNAME_STRING                        "name=\""

#define NGX_UPLOAD_MALFORMED    -1
#define NGX_UPLOAD_NOMEM        -2
#define NGX_UPLOAD_IOERROR      -3
#define NGX_UPLOAD_SCRIPTERROR  -4

/*
 * State of multipart/form-data parser
 */
typedef enum {
	upload_state_boundary_seek,
	upload_state_after_boundary,
	upload_state_headers,
	upload_state_data,
	upload_state_finish
} upload_state_t;

/*
 * Template for a field to generate in output form
 */
typedef struct {
    ngx_table_elt_t          value;
    ngx_array_t             *field_lengths;
    ngx_array_t             *field_values;
    ngx_array_t             *value_lengths;
    ngx_array_t             *value_values;
} ngx_http_upload_field_template_t;

/*
 * Upload configuration for specific location
 */
typedef struct {
    ngx_str_t         url;
    ngx_path_t        *store_path;
    ngx_uint_t        store_access;
    size_t            buffer_size;
    size_t            max_header_len;
    ngx_array_t       *field_templates;
} ngx_http_upload_loc_conf_t;

/*
 * Upload module context
 */
typedef struct ngx_http_upload_ctx_s {
	ngx_str_t           boundary;
	u_char              *boundary_start;
	u_char              *boundary_pos;

	upload_state_t		state;

	u_char              *header_accumulator;
	u_char              *header_accumulator_end;
	u_char              *header_accumulator_pos;

    ngx_str_t           field_name;
    ngx_str_t           file_name;
    ngx_str_t           content_type;

	u_char              *output_buffer;
	u_char              *output_buffer_end;
	u_char              *output_buffer_pos;

    ngx_pool_t          *pool;

    ngx_int_t (*start_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*finish_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*abort_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
	ngx_int_t (*flush_output_buffer_f)(struct ngx_http_upload_ctx_s *upload_ctx, u_char *buf, size_t len);

    ngx_http_request_t  *request;
    ngx_log_t           *log;

    ngx_file_t          output_file;
    ngx_chain_t         *chain;
    ngx_chain_t         *last;
    ngx_chain_t         *checkpoint;

    unsigned int        first_part:1;
    unsigned int        discard_data:1;
    unsigned int        is_file:1;
} ngx_http_upload_ctx_t;

static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upload_body_handler(ngx_http_request_t *r);

static void *ngx_http_upload_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upload_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_upload_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data);
static char *ngx_http_upload_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u);

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t *u,
    u_char *buf, size_t len);
static ngx_int_t ngx_http_upload_append_field(ngx_http_upload_ctx_t *u,
    ngx_str_t *name, ngx_str_t *value);

static void ngx_http_read_upload_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_upload_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_process_request_body(ngx_http_request_t *r, ngx_chain_t *body);

static ngx_int_t ngx_http_read_upload_client_request_body(ngx_http_request_t *r);

static char *ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * upload_init_ctx
 *
 * Initialize upload context. Memory for upload context which is being passed
 * as upload_ctx parameter could be allocated anywhere and should not be freed
 * prior to upload_shutdown_ctx call.
 *
 * IMPORTANT:
 * 
 * After initialization the following routine SHOULD BE called:
 * 
 * upload_parse_content_type -- to assign part boundary 
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 */
void upload_init_ctx(ngx_http_upload_ctx_t *upload_ctx);

/*
 * upload_shutdown_ctx
 *
 * Shutdown upload context. Discard all remaining data and 
 * free all memory associated with upload context.
 *
 * Parameter:
 *     upload_ctx -- upload context which is being shut down
 * 
 */
void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx);

/*
 * upload_start
 *
 * Starts multipart stream processing. Initializes internal buffers
 * and pointers
 *
 * Parameter:
 *     upload_ctx -- upload context which is being initialized
 * 
 * Return value:
 *               NGX_OK on success
 *               NGX_ERROR if error has occured
 *
 */
ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t  *ulcf);

/*
 * upload_parse_content_type
 *
 * Parse and verify content type from HTTP header, extract boundary and
 * assign it to upload context
 * 
 * Parameters:
 *     upload_ctx -- upload context to populate
 *     content_type -- value of Content-Type header to parse
 *
 * Return value:
 *     NGX_OK on success
 *     NGX_ERROR if error has occured
 */
ngx_int_t upload_parse_content_type(ngx_http_upload_ctx_t *upload_ctx, ngx_str_t *content_type);

/*
 * upload_process_buf
 *
 * Process buffer with multipart stream starting from start and terminating
 * by end, operating on upload_ctx. The header information is accumulated in
 * upload_ctx and could be retrieved using upload_get_file_content_type,
 * upload_get_file_name, upload_get_field_name functions. This call can issue
 * one or more calls to start_upload_file, finish_upload_file, abort_upload_file
 * and flush_output_buffer routines.
 *
 * Returns value > 0 if context is ready to process next portion of data,
 *               = 0 if processing finished and remaining data could be discarded,
 *               -1 stream is malformed
 *               -2 insufficient memory 
 */
int upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);

static ngx_command_t  ngx_http_upload_commands[] = { /* {{{ */

    /*
     * Enables uploads for location and specifies URL to pass modified request to  
     */
    { ngx_string("upload_pass"),
      NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upload_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies base path of file store
     */
    { ngx_string("upload_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_path),
      NULL },

    /*
     * Specifies the access mode for files in store
     */
    { ngx_string("upload_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_access),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * to write data to disk
     */
    { ngx_string("upload_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, buffer_size),
      NULL },

    /*
     * Specifies the maximal length of the part header
     */
    { ngx_string("upload_max_part_header_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_header_len),
      NULL },

    /*
     * Specifies the field to set in altered response body
     */
    { ngx_string("upload_set_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_http_upload_module_ctx = { /* {{{ */
    ngx_http_upload_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upload_create_loc_conf,          /* create location configuration */
    ngx_http_upload_merge_loc_conf            /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_http_upload_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_upload_module_ctx,              /* module context */
    ngx_http_upload_commands,                 /* module directives */
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

static ngx_str_t  ngx_http_upload_field_name = ngx_string("upload_field_name");
static ngx_str_t  ngx_http_upload_content_type = ngx_string("upload_content_type");
static ngx_str_t  ngx_http_upload_file_name = ngx_string("upload_file_name");
static ngx_str_t  ngx_http_upload_tmp_path = ngx_string("upload_tmp_path");

static ngx_str_t  ngx_http_upload_empty_field_value = ngx_null_string;

static ngx_int_t /* {{{ ngx_http_upload_handler */
ngx_http_upload_handler(ngx_http_request_t *r)
{
    ngx_http_upload_loc_conf_t  *ulcf;
    ngx_http_upload_ctx_t     *u;
    ngx_int_t                 rc;

    ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    if (!(r->method & NGX_HTTP_POST))
        return NGX_DECLINED;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if (u == NULL) {
        u = ngx_pcalloc(r->pool, sizeof(ngx_http_upload_ctx_t));
        if (u == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        ngx_http_set_ctx(r, u, ngx_http_upload_module);
    }

    // Check whether Content-Type header is missing
    if(r->headers_in.content_type == NULL) {
        ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno,
                      "missing Content-Type header");
        return NGX_HTTP_BAD_REQUEST;
    }

    u->request = r;
    u->log = r->connection->log;
    u->pool = r->pool;
    u->chain = u->last = u->checkpoint = NULL;

    upload_init_ctx(u);

    if(upload_parse_content_type(u, &r->headers_in.content_type->value) != NGX_OK) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_BAD_REQUEST;
    }

    if(upload_start(u, ulcf) != NGX_OK)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    rc = ngx_http_read_upload_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        return rc;
    }

    return NGX_DONE;
} /* }}} */

static ngx_int_t ngx_http_upload_body_handler(ngx_http_request_t *r) { /* {{{ */
    ngx_http_upload_loc_conf_t  *ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    ngx_http_upload_ctx_t       *ctx = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    ngx_str_t                   args;
    ngx_uint_t                  flags;
    ngx_int_t                   rc;
    ngx_str_t                   *uri;
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;

    /*
     * Append final boundary
     */
    b = ngx_create_temp_buf(r->pool, ctx->boundary.len + 2);

    if (b == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_in_chain = 1;

    cl->buf = b;
    cl->next = NULL;
    
    if(ctx->chain == NULL) {
        ctx->chain = cl;
        ctx->last = cl;
    }else{
        ctx->last->next = cl;
        ctx->last = cl;
    }

    b->last = ngx_cpymem(b->last, ctx->boundary.data, ctx->boundary.len);

    *b->last++ = '-';
    *b->last++ = '-';

    uri = &ulcf->url;

    args.len = 0;
    args.data = NULL;
    flags = 0;

    if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body->bufs = ctx->chain;

    // Recalculate content length
    r->headers_in.content_length_n = 0;

    for(cl = ctx->chain ; cl ; cl = cl->next)
        r->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);

    r->headers_in.content_length->value.data = ngx_palloc(r->pool, NGX_OFF_T_LEN);

    if (r->headers_in.content_length->value.data == NULL) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_in.content_length->value.len =
        ngx_sprintf(r->headers_in.content_length->value.data, "%O", r->headers_in.content_length_n)
            - r->headers_in.content_length->value.data;

    rc = ngx_http_internal_redirect(r, uri, &args);

    if (rc == NGX_ERROR) {
        ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    return rc;
} /* }}} */

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_http_request_t        *r = u->request;
    ngx_http_upload_loc_conf_t  *ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    ngx_file_t  *file = &u->output_file;
    ngx_path_t  *path = ulcf->store_path;
    uint32_t    n;
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_err_t   err;
    ngx_http_upload_field_template_t    *t;
    ngx_str_t   field_name, field_value;

    if(u->is_file) {
        file->name.len = path->name.len + 1 + path->len + 10;

        file->name.data = ngx_palloc(u->pool, file->name.len + 1);

        if(file->name.data == NULL)
            return NGX_UPLOAD_NOMEM;

        ngx_memcpy(file->name.data, path->name.data, path->name.len);

        file->log = u->log;

        for(;;) {
            n = (uint32_t) ngx_next_temp_number(0);

            (void) ngx_sprintf(file->name.data + path->name.len + 1 + path->len,
                               "%010uD%Z", n);

            ngx_create_hashed_filename(path, file->name.data, file->name.len);

            ngx_log_debug1(NGX_LOG_DEBUG_CORE, file->log, 0,
                           "hashed path: %s", file->name.data);

            file->fd = ngx_open_tempfile(file->name.data, 1, ulcf->store_access);

            if (file->fd != NGX_INVALID_FILE) {
                file->offset = 0;
                break;
            }

            err = ngx_errno;

            if (err == NGX_EEXIST) {
                n = (uint32_t) ngx_next_temp_number(1);
                continue;
            }

            ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno,
                          "failed to create output file \"%s\" for \"%s\"", file->name.data, u->file_name.data);
            return NGX_UPLOAD_IOERROR;
        }

        if(ulcf->field_templates) {
            t = ulcf->field_templates->elts;
            for (i = 0; i < ulcf->field_templates->nelts; i++) {

                if (t[i].field_lengths == NULL) {
                    field_name = t[i].value.key;
                }else{
                    if (ngx_http_script_run(r, &field_name, t[i].field_lengths->elts, 0,
                        t[i].field_values->elts) == NULL)
                    {
                        return NGX_UPLOAD_SCRIPTERROR;
                    }
                }

                if (t[i].value_lengths == NULL) {
                    field_value = t[i].value.value;
                }else{
                    if (ngx_http_script_run(r, &field_value, t[i].value_lengths->elts, 0,
                        t[i].value_values->elts) == NULL)
                    {
                        return NGX_UPLOAD_SCRIPTERROR;
                    }
                }

                rc = ngx_http_upload_append_field(u, &field_name, &field_value);

                if(rc != NGX_OK)
                    return rc;
            }
        }

        ngx_log_error(NGX_LOG_INFO, u->log, 0
            , "started uploading file \"%s\" to \"%s\" (field \"%s\", content type \"%s\")"
            , u->file_name.data
            , u->output_file.name.data
            , u->field_name.data
            , u->content_type.data
            );
    }else{
        /*
         * Here we do a small hack: the content of a normal field
         * is not known until ngx_http_upload_flush_output_buffer
         * is called. We pass empty field value to simplify things.
         */
        rc = ngx_http_upload_append_field(u, &u->field_name, &ngx_http_upload_empty_field_value);

        if(rc != NGX_OK)
            return rc;
    }

    return NGX_OK;
} /* }}} */

static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    if(u->is_file) {
        ngx_close_file(u->output_file.fd);

        ngx_log_error(NGX_LOG_INFO, u->log, 0
            , "finished uploading file \"%s\" to \"%s\""
            , u->file_name.data
            , u->output_file.name.data
            );
    }

    // Checkpoint current output chain state
    u->checkpoint = u->last;
} /* }}} */

static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    if(u->is_file) {

        ngx_close_file(u->output_file.fd);

        if(ngx_delete_file(u->output_file.name.data) == NGX_FILE_ERROR) { 
            ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno
                , "aborted uploading file \"%s\" to \"%s\", failed to remove destination file"
                , u->file_name.data
                , u->output_file.name.data);
        } else {
            ngx_log_error(NGX_LOG_ALERT, u->log, 0
                , "aborted uploading file \"%s\" to \"%s\", dest file removed"
                , u->file_name.data
                , u->output_file.name.data);
        }
    }

    // Rollback output chain to the previous consistant state
    if(u->checkpoint != NULL) {
        u->last = u->checkpoint;
        u->last->next = NULL;
    }else{
        u->chain = u->last = NULL;
        u->first_part = 1;
    }
} /* }}} */

static ngx_int_t ngx_http_upload_flush_output_buffer(ngx_http_upload_ctx_t *u, u_char *buf, size_t len) { /* {{{ */
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;

    if(u->is_file) {
        if(ngx_write_file(&u->output_file, buf, len, u->output_file.offset) == NGX_ERROR) {
            ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno,
                           "write to file \"%s\" failed", u->output_file.name.data);
            return NGX_UPLOAD_IOERROR;
        }else
            return NGX_OK;
    }else{
        b = ngx_create_temp_buf(u->pool, len);

        if (b == NULL) {
            return NGX_ERROR;
        }

        cl = ngx_alloc_chain_link(u->pool);
        if (cl == NULL) {
            return NGX_ERROR;
        }

        b->last_in_chain = 0;

        cl->buf = b;
        cl->next = NULL;

        b->last = ngx_cpymem(b->last, buf, len);

        if(u->chain == NULL) {
            u->chain = cl;
            u->last = cl;
        }else{
            u->last->next = cl;
            u->last = cl;
        }

        return NGX_OK;
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_append_field */
ngx_http_upload_append_field(ngx_http_upload_ctx_t *u, ngx_str_t *name, ngx_str_t *value)
{
    ngx_int_t   len;
    ngx_chain_t *cl;
    ngx_buf_t *b;

    len = u->first_part ? u->boundary.len - 2 : u->boundary.len;

    len += sizeof("\r\nContent-Disposition: form-data; name=\"") - 1;

    len += name->len;

    len += sizeof("\"\r\n\r\n") - 1;

    len += value->len;

    b = ngx_create_temp_buf(u->pool, len);

    if (b == NULL) {
        return NGX_UPLOAD_NOMEM;
    }

    cl = ngx_alloc_chain_link(u->pool);
    if (cl == NULL) {
        return NGX_UPLOAD_NOMEM;
    }

    b->last = ngx_cpymem(b->last, u->first_part ? u->boundary.data + 2 : u->boundary.data,
        u->first_part ? u->boundary.len - 2 : u->boundary.len);

    b->last = ngx_cpymem(b->last, "\r\nContent-Disposition: form-data; name=\"", sizeof("\r\nContent-Disposition: form-data; name=\"") - 1);

    b->last = ngx_cpymem(b->last, name->data, name->len);

    b->last = ngx_cpymem(b->last, "\"\r\n\r\n", sizeof("\"\r\n\r\n") - 1);

    b->last = ngx_cpymem(b->last, value->data, value->len);

    b->last_in_chain = 0;

    cl->buf = b;
    cl->next = NULL;

    if(u->chain == NULL) {
        u->chain = cl;
        u->last = cl;
    }else{
        u->last->next = cl;
        u->last = cl;
    }

    u->first_part = 0;

    return NGX_OK;
} /* }}} */

static void * /* {{{ ngx_http_upload_create_loc_conf */
ngx_http_upload_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_upload_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_upload_loc_conf_t));
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }

    conf->store_access = NGX_CONF_UNSET_UINT;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_header_len = NGX_CONF_UNSET_SIZE;

    return conf;
} /* }}} */

static char * /* {{{ ngx_http_upload_merge_loc_conf */
ngx_http_upload_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_upload_loc_conf_t  *prev = parent;
    ngx_http_upload_loc_conf_t  *conf = child;

    ngx_conf_merge_str_value(conf->url, prev->url, "");

    ngx_conf_merge_path_value(conf->store_path,
                              prev->store_path,
                              NGX_HTTP_PROXY_TEMP_PATH, 1, 2, 0,
                              ngx_garbage_collector_temp_handler, cf);

    ngx_conf_merge_uint_value(conf->store_access,
                              prev->store_access, 0600);

    ngx_conf_merge_size_value(conf->buffer_size,
                              prev->buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_size_value(conf->max_header_len,
                              prev->max_header_len,
                              (size_t) 512);

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_add_variables */
ngx_http_upload_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var;

    var = ngx_http_add_variable(cf, &ngx_http_upload_field_name,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);

    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_upload_variable;
    var->data = offsetof(ngx_http_upload_ctx_t, field_name);

    var = ngx_http_add_variable(cf, &ngx_http_upload_content_type,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);

    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_upload_variable;
    var->data = offsetof(ngx_http_upload_ctx_t, content_type);

    var = ngx_http_add_variable(cf, &ngx_http_upload_file_name,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_upload_variable;
    var->data = offsetof(ngx_http_upload_ctx_t, file_name);

    var = ngx_http_add_variable(cf, &ngx_http_upload_tmp_path,
        NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH);
    if (var == NULL) {
        return NGX_ERROR;
    }

    var->get_handler = ngx_http_upload_variable;
    var->data = offsetof(ngx_http_upload_ctx_t, output_file.name);

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_variable */
ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    ngx_str_t              *value;

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (ngx_str_t *) ((char *) u + data);

    v->data = value->data;
    v->len = value->len;

    return NGX_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_set_form_field */
ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf = conf;

    ngx_int_t                   n;
    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;
    ngx_http_upload_field_template_t *h;

    value = cf->args->elts;

    if (ulcf->field_templates == NULL) {
        ulcf->field_templates = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_upload_field_template_t));
        if (ulcf->field_templates == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(ulcf->field_templates);
    if (h == NULL) {
        return NGX_CONF_ERROR;
    }

    h->value.hash = 1;
    h->value.key = value[1];
    h->value.value = value[2];
    h->field_lengths = NULL;
    h->field_values = NULL;
    h->value_lengths = NULL;
    h->value_values = NULL;

    /*
     * Compile field name
     */
    n = ngx_http_script_variables_count(&value[1]);

    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[1];
    sc.lengths = &h->field_lengths;
    sc.values = &h->field_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);

    if (n == 0) {
        return NGX_CONF_OK;
    }

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = &value[2];
    sc.lengths = &h->value_lengths;
    sc.values = &h->value_values;
    sc.variables = n;
    sc.complete_lengths = 1;
    sc.complete_values = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_pass  */
ngx_http_upload_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_core_loc_conf_t    *clcf;
    ngx_http_upload_loc_conf_t  *ulcf = conf;

    ngx_str_t                   *value, *url;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_upload_handler;

    value = cf->args->elts;

    url = &value[1];

    ulcf->url = *url;

    return NGX_CONF_OK;
} /* }}} */

ngx_int_t /* {{{ ngx_http_read_upload_client_request_body */
ngx_http_read_upload_client_request_body(ngx_http_request_t *r) {
    ssize_t                    size, preread;
    ngx_buf_t                 *b;
    ngx_chain_t               *cl, **next;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_upload_ctx_t     *u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if (r->request_body || r->discard_body) {
        return NGX_OK;
    }

    rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t));
    if (rb == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body = rb;

    if (r->headers_in.content_length_n <= 0) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_BAD_REQUEST;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     rb->bufs = NULL;
     *     rb->buf = NULL;
     *     rb->rest = 0;
     */

    preread = r->header_in->last - r->header_in->pos;

    if (preread) {

        /* there is the pre-read part of the request body */

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "http client request body preread %uz", preread);

        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        b->temporary = 1;
        b->start = r->header_in->pos;
        b->pos = r->header_in->pos;
        b->last = r->header_in->last;
        b->end = r->header_in->end;

        rb->bufs = ngx_alloc_chain_link(r->pool);
        if (rb->bufs == NULL) {
            upload_shutdown_ctx(u);
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        rb->bufs->buf = b;
        rb->bufs->next = NULL;

        if (preread >= r->headers_in.content_length_n) {

            /* the whole request body was pre-read */

            r->header_in->pos += r->headers_in.content_length_n;
            r->request_length += r->headers_in.content_length_n;

            if (ngx_http_process_request_body(r, rb->bufs) != NGX_OK) {
                upload_shutdown_ctx(u);
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            
            upload_shutdown_ctx(u);

            return ngx_http_upload_body_handler(r);
        }

        /*
         * to not consider the body as pipelined request in
         * ngx_http_set_keepalive()
         */
        r->header_in->pos = r->header_in->last;

        r->request_length += preread;

        rb->rest = r->headers_in.content_length_n - preread;

        if (rb->rest <= (size_t) (b->end - b->last)) {

            /* the whole request body may be placed in r->header_in */

            rb->buf = b;

            r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

            return ngx_http_do_read_upload_client_request_body(r);
        }

        next = &rb->bufs->next;

    } else {
        b = NULL;
        rb->rest = r->headers_in.content_length_n;
        next = &rb->bufs;
    }

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    size = clcf->client_body_buffer_size;
    size += size >> 2;

    if (rb->rest < (size_t) size) {
        size = rb->rest;

        if (r->request_body_in_single_buf) {
            size += preread;
        }

    } else {
        size = clcf->client_body_buffer_size;

        /* disable copying buffer for r->request_body_in_single_buf */
        b = NULL;
    }

    rb->buf = ngx_create_temp_buf(r->pool, size);
    if (rb->buf == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        upload_shutdown_ctx(u);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl->buf = rb->buf;
    cl->next = NULL;

    if (b && r->request_body_in_single_buf) {
        size = b->last - b->pos;
        ngx_memcpy(rb->buf->pos, b->pos, size);
        rb->buf->last += size;

        next = &rb->bufs;
    }

    *next = cl;

    rb->to_write = rb->bufs;

    r->read_event_handler = ngx_http_read_upload_client_request_body_handler;

    return ngx_http_do_read_upload_client_request_body(r);
} /* }}} */

static void /* {{{ ngx_http_read_upload_client_request_body_handler */
ngx_http_read_upload_client_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t  rc;
    ngx_http_upload_ctx_t     *u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if (r->connection->read->timedout) {
        r->connection->timedout = 1;
        upload_shutdown_ctx(u);
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }

    rc = ngx_http_do_read_upload_client_request_body(r);

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        upload_shutdown_ctx(u);
        ngx_http_finalize_request(r, rc);
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_do_read_upload_client_request_body */
ngx_http_do_read_upload_client_request_body(ngx_http_request_t *r)
{
    size_t                     size;
    ssize_t                    n;
    ngx_connection_t          *c;
    ngx_http_request_body_t   *rb;
    ngx_http_core_loc_conf_t  *clcf;
    ngx_http_upload_ctx_t     *u = ngx_http_get_module_ctx(r, ngx_http_upload_module);
    ngx_int_t                  rc;

    c = r->connection;
    rb = r->request_body;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http read client request body");

    for ( ;; ) {
        for ( ;; ) {
            if (rb->buf->last == rb->buf->end) {

                rc = ngx_http_process_request_body(r, rb->to_write);

                switch(rc) {
                    case NGX_OK:
                        break;
                    case NGX_UPLOAD_MALFORMED:
                        return NGX_HTTP_BAD_REQUEST;
                    case NGX_UPLOAD_IOERROR:
                        return NGX_HTTP_SERVICE_UNAVAILABLE;
                    case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
                    default:
                        return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                rb->to_write = rb->bufs->next ? rb->bufs->next : rb->bufs;
                rb->buf->last = rb->buf->start;
            }

            size = rb->buf->end - rb->buf->last;

            if (size > rb->rest) {
                size = rb->rest;
            }

            n = c->recv(c, rb->buf->last, size);

            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                           "http client request body recv %z", n);

            if (n == NGX_AGAIN) {
                break;
            }

            if (n == 0) {
                ngx_log_error(NGX_LOG_INFO, c->log, 0,
                              "client closed prematurely connection");
            }

            if (n == 0 || n == NGX_ERROR) {
                c->error = 1;
                return NGX_HTTP_BAD_REQUEST;
            }

            rb->buf->last += n;
            rb->rest -= n;
            r->request_length += n;

            if (rb->rest == 0) {
                break;
            }

            if (rb->buf->last < rb->buf->end) {
                break;
            }
        }

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, c->log, 0,
                       "http client request body rest %uz", rb->rest);

        if (rb->rest == 0) {
            break;
        }

        if (!c->read->ready) {
            clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, clcf->client_body_timeout);

            if (ngx_handle_read_event(c->read, 0) == NGX_ERROR) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            return NGX_AGAIN;
        }
    }

    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    rc = ngx_http_process_request_body(r, rb->to_write);

    switch(rc) {
        case NGX_OK:
            break;
        case NGX_UPLOAD_MALFORMED:
            return NGX_HTTP_BAD_REQUEST;
        case NGX_UPLOAD_IOERROR:
            return NGX_HTTP_SERVICE_UNAVAILABLE;
        case NGX_UPLOAD_NOMEM: case NGX_UPLOAD_SCRIPTERROR:
        default:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    upload_shutdown_ctx(u);

    return ngx_http_upload_body_handler(r);
} /* }}} */

static ngx_int_t /* {{{ ngx_http_process_request_body */
ngx_http_process_request_body(ngx_http_request_t *r, ngx_chain_t *body)
{
    ngx_int_t rc;
    ngx_http_upload_ctx_t     *u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    // Feed all the buffers into multipart/form-data processor
    while(body) {
        rc = upload_process_buf(u, body->buf->pos, body->buf->last);

        if(rc != NGX_OK)
            return rc;

        // Signal end of body
        if(body->buf->last_buf) {
            rc = upload_process_buf(u, body->buf->pos, body->buf->pos);

            if(rc != NGX_OK)
                return rc;
        }

        body = body->next;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_part_header(ngx_http_upload_ctx_t *upload_ctx, char *header, char *header_end) { /* {{{ */
    if(!strncasecmp(CONTENT_DISPOSITION_STRING, header, sizeof(CONTENT_DISPOSITION_STRING) - 1)) {
        char *p = header + sizeof(CONTENT_DISPOSITION_STRING) - 1;
        char *filename_start, *filename_end;
        char *fieldname_start, *fieldname_end;

        p += strspn(p, " ");
        
        if(strncasecmp(FORM_DATA_STRING, p, sizeof(FORM_DATA_STRING)-1) && 
                strncasecmp(ATTACHMENT_STRING, p, sizeof(ATTACHMENT_STRING)-1)) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "Content-Disposition is not form-data or attachment");
            return NGX_UPLOAD_MALFORMED;
        }

        filename_start = strstr(p, FILENAME_STRING);

        if(filename_start != 0) {
            char *q;
            
            filename_start += sizeof(FILENAME_STRING)-1;

            filename_end = filename_start + strcspn(filename_start, "\"");

            if(*filename_end != '\"') {
                ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                               "malformed filename in part header");
                return NGX_UPLOAD_MALFORMED;
            }

            /*
             * IE sends full path, strip path from filename 
             * Also strip all UNIX path references
             */
            for(q = filename_end-1; q > filename_start; q--)
                if(*q == '\\' || *q == '/') {
                    filename_start = q+1;
                    break;
                }

            upload_ctx->file_name.len = filename_end - filename_start;
            upload_ctx->file_name.data = ngx_pcalloc(upload_ctx->pool, upload_ctx->file_name.len + 1);
            
            if(upload_ctx->file_name.data == NULL)
                return NGX_UPLOAD_NOMEM;

            strncpy((char*)upload_ctx->file_name.data, filename_start, filename_end - filename_start);
        }

        fieldname_start = p;

        do{
            fieldname_start = strstr(fieldname_start, FIELDNAME_STRING);
        }while((fieldname_start != 0) && (fieldname_start + sizeof(FIELDNAME_STRING) - 1 == filename_start));

        if(fieldname_start != 0) {
            fieldname_start += sizeof(FIELDNAME_STRING)-1;

            if(fieldname_start != filename_start) {
                fieldname_end = fieldname_start + strcspn(fieldname_start, "\"");

                if(*fieldname_end != '\"') {
                    ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                                   "malformed filename in part header");
                    return NGX_UPLOAD_MALFORMED;
                }

                upload_ctx->field_name.len = fieldname_end - fieldname_start;
                upload_ctx->field_name.data = ngx_pcalloc(upload_ctx->pool, upload_ctx->field_name.len + 1);

                if(upload_ctx->field_name.data == NULL)
                    return NGX_UPLOAD_NOMEM;

                strncpy((char*)upload_ctx->field_name.data, fieldname_start, fieldname_end - fieldname_start);
            }
        }
    }else if(!strncasecmp(CONTENT_TYPE_STRING, header, sizeof(CONTENT_TYPE_STRING)-1)) {
        char *content_type_str = header + sizeof(CONTENT_TYPE_STRING)-1;
        
        content_type_str += strspn(content_type_str, " ");
        upload_ctx->content_type.len = header_end - content_type_str;
        
        if(upload_ctx->content_type.len == 0) {
            ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                           "empty Content-Type in part header");
            return NGX_UPLOAD_MALFORMED; // Empty Content-Type field
        }

        upload_ctx->content_type.data = ngx_pcalloc(upload_ctx->pool, upload_ctx->content_type.len + 1);
        
        if(upload_ctx->content_type.data == NULL)
            return NGX_UPLOAD_NOMEM; // Unable to allocate memory for string

        strncpy((char*)upload_ctx->content_type.data, content_type_str, upload_ctx->content_type.len);
    }

    return NGX_OK;
} /* }}} */

static void upload_discard_part_attributes(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->file_name.len = 0;
    upload_ctx->file_name.data = NULL;

    upload_ctx->field_name.len = 0;
    upload_ctx->field_name.data = NULL;

    upload_ctx->content_type.len = 0;
    upload_ctx->content_type.data = NULL;
} /* }}} */

static ngx_int_t upload_start_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if(upload_ctx->start_part_f)
        return upload_ctx->start_part_f(upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void upload_finish_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if(upload_ctx->finish_part_f)
        upload_ctx->finish_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_abort_file(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->abort_part_f)
        upload_ctx->abort_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;
} /* }}} */

static void upload_flush_output_buffer(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->output_buffer_pos > upload_ctx->output_buffer) {
        if(upload_ctx->flush_output_buffer_f)
            if(upload_ctx->flush_output_buffer_f(upload_ctx, (void*)upload_ctx->output_buffer, 
                (size_t)(upload_ctx->output_buffer_pos - upload_ctx->output_buffer)) != NGX_OK)
                upload_ctx->discard_data = 1;

        upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
    }
} /* }}} */

void upload_init_ctx(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    upload_ctx->boundary.data = upload_ctx->boundary_start = upload_ctx->boundary_pos = 0;

	upload_ctx->state = upload_state_boundary_seek;

    upload_ctx->content_type.len = 0;
    upload_ctx->content_type.data = NULL;

    upload_ctx->field_name.len = 0;
    upload_ctx->field_name.data = NULL;

    upload_ctx->file_name.len = 0;
    upload_ctx->file_name.data = NULL;

    upload_ctx->discard_data = 0;

	upload_ctx->start_part_f = ngx_http_upload_start_handler;
	upload_ctx->finish_part_f = ngx_http_upload_finish_handler;
	upload_ctx->abort_part_f = ngx_http_upload_abort_handler;
	upload_ctx->flush_output_buffer_f = ngx_http_upload_flush_output_buffer;
} /* }}} */

void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
	if(upload_ctx != 0) {
        // Abort file if we still processing it
        if(upload_ctx->state == upload_state_data) {
            upload_flush_output_buffer(upload_ctx);
            upload_abort_file(upload_ctx);
        }

        upload_discard_part_attributes(upload_ctx);
	}
} /* }}} */

ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t *ulcf) { /* {{{ */
	if(upload_ctx == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator = ngx_pcalloc(upload_ctx->pool, ulcf->max_header_len + 1);

	if(upload_ctx->header_accumulator == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
	upload_ctx->header_accumulator_end = upload_ctx->header_accumulator + ulcf->max_header_len;

	upload_ctx->output_buffer = ngx_pcalloc(upload_ctx->pool, ulcf->buffer_size);

	if(upload_ctx->output_buffer == NULL)
		return NGX_ERROR;

    upload_ctx->output_buffer_pos = upload_ctx->output_buffer;
    upload_ctx->output_buffer_end = upload_ctx->output_buffer + ulcf->buffer_size;

    upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;

    upload_ctx->first_part = 1;

	return NGX_OK;
} /* }}} */

ngx_int_t upload_parse_content_type(ngx_http_upload_ctx_t *upload_ctx, ngx_str_t *content_type) { /* {{{ */
    // Find colon in content type string, which terminates mime type
    char *mime_type_end_ptr = strchr((char*)content_type->data, ';');
    char *boundary_start_ptr, *boundary_end_ptr;

    upload_ctx->boundary.data = 0;

    if(mime_type_end_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED;
    }

    if(strncasecmp(MULTIPART_FORM_DATA_STRING, (char*)content_type->data, (u_char*)mime_type_end_ptr - content_type->data - 1)) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "Content-Type is not multipart/form-data: %s", content_type->data);
        return NGX_UPLOAD_MALFORMED;
    }

    boundary_start_ptr = strstr(mime_type_end_ptr, BOUNDARY_STRING);

    if(boundary_start_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED; // No boundary found
    }

    boundary_start_ptr += sizeof(BOUNDARY_STRING) - 1;
    boundary_end_ptr = boundary_start_ptr + strcspn(boundary_start_ptr, " ;\n\r");

    if(boundary_end_ptr == boundary_start_ptr) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "boundary is empty");
        return NGX_UPLOAD_MALFORMED;
    }

    // Allocate memory for entire boundary plus \r\n plus terminating character
    upload_ctx->boundary.len = boundary_end_ptr - boundary_start_ptr + 4;
    upload_ctx->boundary.data = ngx_pcalloc(upload_ctx->pool, upload_ctx->boundary.len + 1);

    if(upload_ctx->boundary.data == NULL)
        return NGX_UPLOAD_NOMEM;

    strncpy((char*)upload_ctx->boundary.data + 4, boundary_start_ptr, boundary_end_ptr - boundary_start_ptr);
    
    upload_ctx->boundary.data[boundary_end_ptr - boundary_start_ptr + 4] = '\0';

    // Prepend boundary data by \r\n--
    upload_ctx->boundary.data[0] = '\r'; 
    upload_ctx->boundary.data[1] = '\n'; 
    upload_ctx->boundary.data[2] = '-'; 
    upload_ctx->boundary.data[3] = '-'; 

    /*
     * NOTE: first boundary doesn't start with \r\n. Here we
     * advance 2 positions forward. We will return 2 positions back 
     * later
     */
    upload_ctx->boundary_start = upload_ctx->boundary.data + 2;
    upload_ctx->boundary_pos = upload_ctx->boundary_start;

    return NGX_OK;
} /* }}} */

void upload_putc(ngx_http_upload_ctx_t *upload_ctx, u_char c) { /* {{{ */
    if(!upload_ctx->discard_data) {
        *upload_ctx->output_buffer_pos = c;

        upload_ctx->output_buffer_pos++;

        if(upload_ctx->output_buffer_pos == upload_ctx->output_buffer_end)
            upload_flush_output_buffer(upload_ctx);	
    }
} /* }}} */

int upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */

	u_char *p;
    ngx_int_t rc;

	// No more data?
	if(start == end) {
		if(upload_ctx->state != upload_state_finish)
			return NGX_UPLOAD_MALFORMED; // Signal error if still haven't finished
		else
			return NGX_OK; // Otherwise confirm end of stream
    }

	for(p = start; p != end; p++) {
		switch(upload_ctx->state) {
			/*
			 * Seek the boundary
			 */
			case upload_state_boundary_seek:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else
					upload_ctx->boundary_pos = upload_ctx->boundary_start;

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_start = upload_ctx->boundary.data;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;
				}
				break;
			case upload_state_after_boundary:
				switch(*p) {
					case '\n':
						upload_ctx->state = upload_state_headers;
                        upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
					case '\r':
						break;
					case '-':
						upload_ctx->state = upload_state_finish;
						break;
				}
				break;
			/*
			 * Collect and store headers
			 */
			case upload_state_headers:
				switch(*p) {
					case '\n':
						if(upload_ctx->header_accumulator_pos == upload_ctx->header_accumulator) {
                            upload_ctx->is_file = (upload_ctx->file_name.data == 0) || (upload_ctx->file_name.len == 0) ? 0 : 1;

                            rc = upload_start_file(upload_ctx);
                            
                            if(rc != NGX_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // User requested to cancel processing
                            } else {
                                upload_ctx->state = upload_state_data;
                                upload_ctx->output_buffer_pos = upload_ctx->output_buffer;	
                            }
                        } else {
                            *upload_ctx->header_accumulator_pos = '\0';

                            rc = upload_parse_part_header(upload_ctx, (char*)upload_ctx->header_accumulator,
                                (char*)upload_ctx->header_accumulator_pos);

                            if(rc != NGX_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // Malformed header
                            } else
                                upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
                        }
					case '\r':
						break;
					default:
						if(upload_ctx->header_accumulator_pos < upload_ctx->header_accumulator_end - 1)
							*upload_ctx->header_accumulator_pos++ = *p;
						else {
                            upload_ctx->state = upload_state_finish;
							return NGX_UPLOAD_MALFORMED; // Header is too long
                        }
						break;
				}
				break;
			/*
			 * Search for separating or terminating boundary
			 * and output data simultaneously
			 */
			case upload_state_data:
				if(*p == *upload_ctx->boundary_pos) 
					upload_ctx->boundary_pos++;
				else {
					if(upload_ctx->boundary_pos == upload_ctx->boundary_start) {
                        // IE 5.0 bug workaround
                        if(*p == '\n') {
                            /*
                             * Set current matched position beyond LF and prevent outputting
                             * CR in case of unsuccessful match by altering boundary_start 
                             */ 
                            upload_ctx->boundary_pos = upload_ctx->boundary.data + 2;
                            upload_ctx->boundary_start = upload_ctx->boundary.data + 1;
                        } else
                            upload_putc(upload_ctx, *p);
                    } else {
						// Output partially matched lump of boundary
						u_char *q;
						for(q = upload_ctx->boundary_start; q != upload_ctx->boundary_pos; q++)
							upload_putc(upload_ctx, *q);

                        p--; // Repeat reading last character

						// And reset matched position
                        upload_ctx->boundary_start = upload_ctx->boundary.data;
						upload_ctx->boundary_pos = upload_ctx->boundary_start;
					}
				}

				if(upload_ctx->boundary_pos == upload_ctx->boundary.data + upload_ctx->boundary.len) {
					upload_ctx->state = upload_state_after_boundary;
					upload_ctx->boundary_pos = upload_ctx->boundary_start;

                    upload_flush_output_buffer(upload_ctx);
                    if(!upload_ctx->discard_data)
                        upload_finish_file(upload_ctx);
                    else
                        upload_abort_file(upload_ctx);
				}
				break;
			/*
			 * Skip trailing garbage
			 */
			case upload_state_finish:
				break;
		}
	}

	return NGX_OK;
} /* }}} */

