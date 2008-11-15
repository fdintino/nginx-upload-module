/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 * Client body reception code Copyright (c) 2002-2007 Igor Sysoev
 * Temporary file name generation code Copyright (c) 2002-2007 Igor Sysoev
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_upload.h>

static ngx_int_t ngx_http_upload_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_upload_body_handler(ngx_http_request_t *r);

static void *ngx_http_upload_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_upload_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_upload_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_sha1_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_file_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_upload_crc32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static char *ngx_http_upload_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_upload_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u);

static ngx_int_t ngx_http_upload_process_chain(ngx_http_upload_ctx_t *u,
    ngx_chain_t *chain);

static ngx_int_t ngx_http_upload_field_start(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_field_finish(ngx_http_upload_ctx_t *u);
static void ngx_http_upload_field_abort(ngx_http_upload_ctx_t *u);
static ngx_int_t ngx_http_upload_field_process_chain(ngx_http_upload_ctx_t *u,
    ngx_chain_t *chain);

static ngx_int_t ngx_http_upload_append_field(ngx_http_upload_ctx_t *u,
    ngx_str_t *name, ngx_str_t *value);

static void ngx_http_read_upload_client_request_body_handler(ngx_http_request_t *r);
static ngx_int_t ngx_http_do_read_upload_client_request_body(ngx_http_request_t *r);
static ngx_int_t ngx_http_process_request_body(ngx_http_request_t *r, ngx_chain_t *body);

static ngx_int_t ngx_http_read_upload_client_request_body(ngx_http_request_t *r);

static char *ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upload_pass_form_field(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_http_upload_cleanup(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static void ngx_upload_cleanup_handler(void *data);

static char *ngx_http_upload_filter_block(ngx_conf_t *cf, ngx_command_t *cmd,
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
static void upload_init_ctx(ngx_http_upload_ctx_t *upload_ctx);

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
static void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx);

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
static ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t  *ulcf);

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
static ngx_int_t upload_parse_content_type(ngx_http_upload_ctx_t *upload_ctx, ngx_str_t *content_type);

/*
 * upload_process_buf
 *
 * Process buffer with multipart stream starting from start and terminating
 * by end, operating on upload_ctx. The header information is accumulated in
 * This call can invoke one or more calls to start_upload_file, finish_upload_file,
 * abort_upload_file and flush_output_buffer routines.
 *
 * Returns value NGX_OK successful
 *               NGX_UPLOAD_MALFORMED stream is malformed
 *               NGX_UPLOAD_NOMEM insufficient memory 
 *               NGX_UPLOAD_IOERROR input-output error
 *               NGX_UPLOAD_SCRIPTERROR nginx script engine failed
 *               NGX_UPLOAD_TOOLARGE part body is too large
 */
static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end);

static ngx_upload_content_filter_t ngx_write_content_filter = { /* {{{ */
    ngx_http_upload_start_handler,
    ngx_http_upload_finish_handler,
    ngx_http_upload_abort_handler,
    ngx_http_upload_process_chain
}; /* }}} */

static ngx_upload_field_filter_t ngx_write_field_filter = { /* {{{ */
    ngx_http_upload_field_start,
    ngx_http_upload_field_finish,
    ngx_http_upload_field_abort,
    ngx_http_upload_field_process_chain
}; /* }}} */

static ngx_command_t  ngx_http_upload_commands[] = { /* {{{ */

    /*
     * Enables uploads for location and specifies location to pass modified request to  
     */
    { ngx_string("upload_pass"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_upload_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    /*
     * Specifies base path of file store
     */
    { ngx_string("upload_store"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1234,
      ngx_conf_set_path_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_path),
      NULL },

    /*
     * Specifies the access mode for files in store
     */
    { ngx_string("upload_store_access"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_access_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, store_access),
      NULL },

    /*
     * Specifies the size of buffer, which will be used
     * to write data to disk
     */
    { ngx_string("upload_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, buffer_size),
      NULL },

    /*
     * Specifies the maximal length of the part header
     */
    { ngx_string("upload_max_part_header_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_header_len),
      NULL },

    /*
     * Specifies the maximal size of the file to be uploaded
     */
    { ngx_string("upload_max_file_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_off_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_file_size),
      NULL },

    /*
     * Specifies the maximal length of output body
     */
    { ngx_string("upload_max_output_body_len"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, max_output_body_len),
      NULL },

    /*
     * Specifies the field to set in altered response body
     */
    { ngx_string("upload_set_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, field_templates),
      NULL},

    /*
     * Specifies the field with aggregate parameters
     * to set in altered response body
     */
    { ngx_string("upload_aggregate_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE2,
      ngx_http_upload_set_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates),
      NULL},

    /*
     * Specifies the field to pass to backend
     */
    { ngx_string("upload_pass_form_field"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_TAKE1,
      ngx_http_upload_pass_form_field,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    /*
     * Specifies http statuses upon reception of
     * which cleanup of uploaded files will be initiated
     */
    { ngx_string("upload_cleanup"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                        |NGX_CONF_1MORE,
      ngx_http_upload_cleanup,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    /*
     * Specifies a content filter for files of specified mime type
     */
    { ngx_string("upload_filter"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_BLOCK|NGX_CONF_1MORE,
      ngx_http_upload_filter_block,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL},

    /*
     * Specifies a separator for archive element tokens
     */
    { ngx_string("upload_archive_elm_separator"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, archive_elm_separator),
      NULL},

    /*
     * Specifies a separator for archive path tokens
     */
    { ngx_string("upload_archive_path_separator"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_upload_loc_conf_t, archive_path_separator),
      NULL},
     
     /*
      * Specifies the whether or not to forward query args
      * to the upload_pass redirect location
      */
     { ngx_string("upload_pass_args"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                         |NGX_CONF_FLAG,
       ngx_conf_set_flag_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_upload_loc_conf_t, forward_args),
       NULL },

     /*
      * Specifies the whether or not to guess content type
      * via file extension for specified content types
      */
     { ngx_string("upload_void_content_types"),
       NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF
                         |NGX_CONF_1MORE,
       ngx_conf_set_str_array_slot,
       NGX_HTTP_LOC_CONF_OFFSET,
       offsetof(ngx_http_upload_loc_conf_t, void_content_types),
       NULL },

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_http_upload_module_ctx = { /* {{{ */
    ngx_http_upload_add_variables,         /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_upload_create_loc_conf,       /* create location configuration */
    ngx_http_upload_merge_loc_conf         /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_http_upload_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_http_upload_module_ctx,           /* module context */
    ngx_http_upload_commands,              /* module directives */
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

static ngx_http_variable_t  ngx_http_upload_variables[] = { /* {{{ */

    { ngx_string("upload_field_name"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, field_name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_content_type"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, content_type),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_name"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, file_name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_tmp_path"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, output_file.name),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_archive_elm"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, archive_elm),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_archive_path"), NULL, ngx_http_upload_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, archive_path),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_http_variable_t  ngx_http_upload_aggregate_variables[] = { /* {{{ */

    { ngx_string("upload_file_md5"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t) "0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_md5_uc"), NULL, ngx_http_upload_md5_variable,
      (uintptr_t) "0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t) "0123456789abcdef",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_sha1_uc"), NULL, ngx_http_upload_sha1_variable,
      (uintptr_t) "0123456789ABCDEF",
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_crc32"), NULL, ngx_http_upload_crc32_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, crc32),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_string("upload_file_size"), NULL, ngx_http_upload_file_size_variable,
      (uintptr_t) offsetof(ngx_http_upload_ctx_t, output_file.offset),
      NGX_HTTP_VAR_CHANGEABLE|NGX_HTTP_VAR_NOCACHEABLE|NGX_HTTP_VAR_NOHASH, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
}; /* }}} */

static ngx_str_t  ngx_http_upload_empty_field_value = ngx_null_string;

static ngx_str_t  ngx_upload_field_part1 = { /* {{{ */
    sizeof(CRLF "Content-Disposition: form-data; name=\"") - 1,
    (u_char*)CRLF "Content-Disposition: form-data; name=\""
}; /* }}} */

static ngx_str_t  ngx_upload_field_part2 = { /* {{{ */
    sizeof("\"" CRLF CRLF) - 1,
    (u_char*)"\"" CRLF CRLF
}; /* }}} */

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

    if(ulcf->md5) {
        if(u->md5_ctx == NULL) {
            u->md5_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_md5_ctx_t));
            if (u->md5_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->md5_ctx = NULL;

    if(ulcf->sha1) {
        if(u->sha1_ctx == NULL) {
            u->sha1_ctx = ngx_palloc(r->pool, sizeof(ngx_http_upload_sha1_ctx_t));
            if (u->sha1_ctx == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
        }
    }else
        u->sha1_ctx = NULL;

    u->calculate_crc32 = ulcf->crc32;

    // Check whether Content-Type header is missing
    if(r->headers_in.content_type == NULL) {
        ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno,
                      "missing Content-Type header");
        return NGX_HTTP_BAD_REQUEST;
    }

    u->request = r;
    u->log = r->connection->log;
    u->chain = u->last = u->checkpoint = NULL;
    u->output_body_len = 0;

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

    if(ulcf->max_output_body_len != 0) {
        if(ctx->output_body_len + ctx->boundary.len + 4 > ulcf->max_output_body_len)
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
    }

    /*
     * Append final boundary
     */
    b = ngx_create_temp_buf(r->pool, ctx->boundary.len + 4);

    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->last_in_chain = 1;
    b->last_buf = 1;

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
    *b->last++ = CR;
    *b->last++ = LF;

    uri = &ulcf->url;

    if (ulcf->forward_args) {
      args = r->args; /* forward the query args */
    }
    else {
      args.len = 0;
      args.data = NULL;
    }

    flags = 0;

    if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->request_body->bufs = ctx->chain;

    // Recalculate content length
    r->headers_in.content_length_n = 0;

    for(cl = ctx->chain ; cl ; cl = cl->next)
        r->headers_in.content_length_n += (cl->buf->last - cl->buf->pos);

    r->headers_in.content_length->value.data = ngx_palloc(r->pool, NGX_OFF_T_LEN);

    if (r->headers_in.content_length->value.data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->headers_in.content_length->value.len =
        ngx_sprintf(r->headers_in.content_length->value.data, "%O", r->headers_in.content_length_n)
            - r->headers_in.content_length->value.data;

    rc = ngx_http_internal_redirect(r, uri, &args);

    if (rc == NGX_ERROR) {
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
    ngx_upload_cleanup_t  *ucln;

    u->cln = ngx_pool_cleanup_add(r->pool, sizeof(ngx_upload_cleanup_t));

    if(u->cln == NULL)
        return NGX_UPLOAD_NOMEM;

    file->name.len = path->name.len + 1 + path->len + 10;

    file->name.data = ngx_palloc(u->request->pool, file->name.len + 1);

    if(file->name.data == NULL)
        return NGX_UPLOAD_NOMEM;

    ngx_memcpy(file->name.data, path->name.data, path->name.len);

    file->log = r->connection->log;

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

        ngx_log_error(NGX_LOG_ERR, r->connection->log, ngx_errno,
                      "failed to create output file \"%V\" for \"%V\"", &file->name, &u->file_name);
        return NGX_UPLOAD_IOERROR;
    }

    u->cln->handler = ngx_upload_cleanup_handler;

    ucln = u->cln->data;
    ucln->fd = file->fd;
    ucln->filename = file->name.data;
    ucln->log = r->connection->log;
    ucln->headers_out = &r->headers_out;
    ucln->cleanup_statuses = ulcf->cleanup_statuses;
    ucln->aborted = 0;

    if(ulcf->field_templates) {
        t = ulcf->field_templates->elts;
        for (i = 0; i < ulcf->field_templates->nelts; i++) {

            if (t[i].field_lengths == NULL) {
                field_name = t[i].value.key;
            }else{
                if (ngx_http_script_run(r, &field_name, t[i].field_lengths->elts, 0,
                    t[i].field_values->elts) == NULL)
                {
                    rc = NGX_UPLOAD_SCRIPTERROR;
                    goto cleanup_file;
                }
            }

            if (t[i].value_lengths == NULL) {
                field_value = t[i].value.value;
            }else{
                if (ngx_http_script_run(r, &field_value, t[i].value_lengths->elts, 0,
                    t[i].value_values->elts) == NULL)
                {
                    rc = NGX_UPLOAD_SCRIPTERROR;
                    goto cleanup_file;
                }
            }

            rc = ngx_http_upload_append_field(u, &field_name, &field_value);

            if(rc != NGX_OK)
                goto cleanup_file;
        }
    }

    if(u->md5_ctx != NULL)
        MD5Init(&u->md5_ctx->md5);

    if(u->sha1_ctx != NULL)
        SHA1_Init(&u->sha1_ctx->sha1);

    if(u->calculate_crc32)
        ngx_crc32_init(u->crc32);

    ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
        , "started writing file \"%V\" to \"%V\" (field \"%V\", content type \"%V\")"
        , &u->file_name
        , &u->output_file.name
        , &u->field_name
        , &u->content_type
        );

    return NGX_OK;

cleanup_file:
    return rc;
} /* }}} */

static void ngx_http_upload_finish_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_http_upload_field_template_t    *af;
    ngx_str_t   aggregate_field_name, aggregate_field_value;
    ngx_http_request_t        *r = u->request;
    ngx_http_upload_loc_conf_t  *ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);
    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_upload_cleanup_t  *ucln;

    if(u->is_file) {
        ucln = u->cln->data;
        ucln->fd = -1;

        ngx_close_file(u->output_file.fd);

        ngx_log_error(NGX_LOG_INFO, r->connection->log, 0
            , "finished writing file \"%V\" to \"%V\""
            , &u->file_name
            , &u->output_file.name
            );

        if(u->md5_ctx)
            MD5Final(u->md5_ctx->md5_digest, &u->md5_ctx->md5);

        if(u->sha1_ctx)
            SHA1_Final(u->sha1_ctx->sha1_digest, &u->sha1_ctx->sha1);

        if(u->calculate_crc32)
            ngx_crc32_final(u->crc32);

        if(ulcf->aggregate_field_templates) {
            af = ulcf->aggregate_field_templates->elts;
            for (i = 0; i < ulcf->aggregate_field_templates->nelts; i++) {

                if (af[i].field_lengths == NULL) {
                    aggregate_field_name = af[i].value.key;
                }else{
                    if (ngx_http_script_run(r, &aggregate_field_name, af[i].field_lengths->elts, 0,
                        af[i].field_values->elts) == NULL)
                    {
                        goto rollback;
                    }
                }

                if (af[i].value_lengths == NULL) {
                    aggregate_field_value = af[i].value.value;
                }else{
                    if (ngx_http_script_run(r, &aggregate_field_value, af[i].value_lengths->elts, 0,
                        af[i].value_values->elts) == NULL)
                    {
                        goto rollback;
                    }
                }

                rc = ngx_http_upload_append_field(u, &aggregate_field_name, &aggregate_field_value);

                if(rc != NGX_OK)
                    goto rollback;
            }
        }
    }

    // Checkpoint current output chain state
    u->checkpoint = u->last;
    return;

rollback:
    ngx_http_upload_abort_handler(u);
} /* }}} */

static void ngx_http_upload_abort_handler(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_upload_cleanup_t  *ucln;

    if(u->is_file) {
        /*
         * Upload of a part could be aborted due to temporary reasons, thus
         * next body part will be potentially processed successfuly.
         *
         * Therefore we don't postpone cleanup to the request finallization
         * in order to save additional resources, instead we mark existing
         * cleanup record as aborted.
         */
        ucln = u->cln->data;
        ucln->fd = -1;
        ucln->aborted = 1;

        ngx_close_file(u->output_file.fd);

        if(ngx_delete_file(u->output_file.name.data) == NGX_FILE_ERROR) { 
            ngx_log_error(NGX_LOG_ERR, u->log, ngx_errno
                , "aborted writing file \"%V\" to \"%V\", failed to remove destination file"
                , &u->file_name
                , &u->output_file.name);
        } else {
            ngx_log_error(NGX_LOG_ALERT, u->log, 0
                , "aborted writing file \"%V\" to \"%V\", dest file removed"
                , &u->file_name
                , &u->output_file.name);
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

static ngx_int_t ngx_http_upload_process_chain(ngx_http_upload_ctx_t *u, ngx_chain_t *chain) { /* {{{ */
    ngx_chain_t                    *cl;
    ngx_http_upload_loc_conf_t     *ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

    for(cl = chain; cl && !cl->buf->last_in_chain; cl = cl->next) {
        if(ulcf->max_file_size != 0) {
            if(u->output_file.offset + (off_t)(cl->buf->last - cl->buf->pos) > ulcf->max_file_size)
                return NGX_UPLOAD_TOOLARGE;
        }

        if(u->md5_ctx)
            MD5Update(&u->md5_ctx->md5, cl->buf->pos, cl->buf->last - cl->buf->pos);

        if(u->sha1_ctx)
            SHA1_Update(&u->sha1_ctx->sha1, cl->buf->pos, cl->buf->last - cl->buf->pos);

        if(u->calculate_crc32)
            ngx_crc32_update(&u->crc32, cl->buf->pos, cl->buf->last - cl->buf->pos);

        if(ngx_write_file(&u->output_file, cl->buf->pos, cl->buf->last - cl->buf->pos,
            u->output_file.offset) == NGX_ERROR)
        {
            return NGX_UPLOAD_IOERROR;
        }

        cl->buf->pos = cl->buf->last;
    }

    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_http_upload_append_str */
ngx_http_upload_append_str(ngx_http_upload_ctx_t *u, ngx_buf_t *b, ngx_chain_t *cl, ngx_str_t *s)
{
    b->start = b->pos = s->data;
    b->end = b->last = s->data + s->len;
    b->memory = 1;
    b->temporary = 1;
    b->in_file = 0;
    b->last_buf = 0;
    b->flush = 0;

    b->last_in_chain = 0;
    b->last_buf = 0;

    cl->buf = b;
    cl->next = NULL;

    if(u->chain == NULL) {
        u->chain = cl;
        u->last = cl;
    }else{
        u->last->next = cl;
        u->last = cl;
    }

    u->output_body_len += s->len;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_append_field */
ngx_http_upload_append_field(ngx_http_upload_ctx_t *u, ngx_str_t *name, ngx_str_t *value)
{
    ngx_str_t   boundary = { u->first_part ? u->boundary.len - 2 : u->boundary.len,
         u->first_part ? u->boundary.data + 2 : u->boundary.data };

    ngx_buf_t *b;
    ngx_chain_t *cl;
    ngx_http_upload_loc_conf_t  *ulcf;

    if(name->len > 0) {
        ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

        if(ulcf->max_output_body_len != 0) {
            if(u->output_body_len + boundary.len + ngx_upload_field_part1.len + name->len
               + ngx_upload_field_part2.len + value->len > ulcf->max_output_body_len)
                return NGX_UPLOAD_TOOLARGE;
        }

        b = ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_buf_t) : 4 * sizeof(ngx_buf_t));

        if (b == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        cl = ngx_palloc(u->request->pool, value->len > 0 ?
            5 * sizeof(ngx_chain_t) : 4 * sizeof(ngx_chain_t));

        if (cl == NULL) {
            return NGX_UPLOAD_NOMEM;
        }

        ngx_http_upload_append_str(u, b, cl, &boundary);

        ngx_http_upload_append_str(u, b + 1, cl + 1, &ngx_upload_field_part1);

        ngx_http_upload_append_str(u, b + 2, cl + 2, name);

        ngx_http_upload_append_str(u, b + 3, cl + 3, &ngx_upload_field_part2);

        if(value->len > 0)
            ngx_http_upload_append_str(u, b + 4, cl + 4, value);

        u->output_body_len += boundary.len + ngx_upload_field_part1.len + name->len
            + ngx_upload_field_part2.len + value->len;

        u->first_part = 0;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t ngx_http_upload_field_start(ngx_http_upload_ctx_t *u) { /* {{{ */
    ngx_http_request_t        *r = u->request;
    ngx_http_upload_loc_conf_t  *ulcf = ngx_http_get_module_loc_conf(r, ngx_http_upload_module);

    ngx_uint_t  i;
    ngx_int_t   rc;
    ngx_http_upload_field_filter_t    *f;
    ngx_uint_t  pass_field;

    pass_field = 0;

    if(ulcf->field_filters) {
        f = ulcf->field_filters->elts;
        for (i = 0; i < ulcf->field_filters->nelts; i++) {
#if (NGX_PCRE)
            rc = ngx_regex_exec(f[i].regex, &u->field_name, NULL, 0);

            if (rc != NGX_REGEX_NO_MATCHED && rc < 0) {
                return NGX_UPLOAD_SCRIPTERROR;
            }

            /*
             * If at least one filter succeeds, we pass the field
             */
            if(rc == 0)
                pass_field = 1;
#else
            if(ngx_strncmp(f[i].text.data, u->field_name.data, u->field_name.len) == 0)
                pass_field = 1;
#endif
        }
    }

    if(pass_field && u->field_name.len > 0) { 
        /*
         * Here we do a small hack: the content of a normal field
         * is not known until ngx_http_upload_flush_output_buffer
         * is called. We pass empty field value to simplify things.
         */
        rc = ngx_http_upload_append_field(u, &u->field_name, &ngx_http_upload_empty_field_value);

        if(rc != NGX_OK)
            return rc;
    }else
        u->discard_data = 1;

    return NGX_OK;
} /* }}} */

static void ngx_http_upload_field_finish(ngx_http_upload_ctx_t *u) { /* {{{ */
    // Checkpoint current output chain state
    u->checkpoint = u->last;
} /* }}} */

static void ngx_http_upload_field_abort(ngx_http_upload_ctx_t *u) { /* {{{ */
    // Rollback output chain to the previous consistant state
    if(u->checkpoint != NULL) {
        u->last = u->checkpoint;
        u->last->next = NULL;
    }else{
        u->chain = u->last = NULL;
        u->first_part = 1;
    }
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_field_process_chain */
ngx_http_upload_field_process_chain(ngx_http_upload_ctx_t *u, ngx_chain_t *chain) {
    ngx_buf_t                      *b;
    ngx_chain_t                    *cl;
    ngx_http_upload_loc_conf_t     *ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

    for(;chain && !chain->buf->last_in_chain; chain = chain->next) {
        if(chain->buf->last - chain->buf->pos > 0) {
            if(ulcf->max_output_body_len != 0) {
                if (u->output_body_len + (size_t)(chain->buf->last - chain->buf->pos) > ulcf->max_output_body_len)
                    return NGX_UPLOAD_TOOLARGE;
            }

            u->output_body_len += (chain->buf->last - chain->buf->pos);

            b = ngx_create_temp_buf(u->request->pool, chain->buf->last - chain->buf->pos);

            if (b == NULL) {
                return NGX_ERROR;
            }

            cl = ngx_alloc_chain_link(u->request->pool);
            if (cl == NULL) {
                return NGX_ERROR;
            }

            b->last_in_chain = 0;

            cl->buf = b;
            cl->next = NULL;

            b->last = ngx_cpymem(b->last, chain->buf->pos, chain->buf->last - chain->buf->pos);

            if(u->chain == NULL) {
                u->chain = cl;
                u->last = cl;
            }else{
                u->last->next = cl;
                u->last = cl;
            }
        }
    }

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
    conf->forward_args = NGX_CONF_UNSET;

    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->max_header_len = NGX_CONF_UNSET_SIZE;
    conf->max_output_body_len = NGX_CONF_UNSET_SIZE;
    conf->max_file_size = NGX_CONF_UNSET;

    conf->void_content_types = NGX_CONF_UNSET_PTR;

    /*
     * conf->archive_elm_separator
     * conf->field_templates,
     * conf->aggregate_field_templates,
     * conf->field_filters are
     * zeroed by ngx_pcalloc
     */

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

    ngx_conf_merge_size_value(conf->max_output_body_len,
                              prev->max_output_body_len,
                              (size_t) 100 * 1024);

    ngx_conf_merge_off_value(conf->max_file_size,
                             prev->max_file_size,
                             0);

    if(conf->forward_args == NGX_CONF_UNSET) {
        conf->forward_args = (prev->forward_args != NGX_CONF_UNSET) ?
            prev->forward_args : 0;
    }

    if(conf->field_templates == NULL) {
        conf->field_templates = prev->field_templates;
    }

    if(conf->aggregate_field_templates == NULL) {
        conf->aggregate_field_templates = prev->aggregate_field_templates;

        if(prev->md5) {
            conf->md5 = prev->md5;
        }

        if(prev->sha1) {
            conf->sha1 = prev->sha1;
        }

        if(prev->crc32) {
            conf->crc32 = prev->crc32;
        }
    }

    if(conf->field_filters == NULL) {
        conf->field_filters = prev->field_filters;
    }

    if(conf->cleanup_statuses == NULL) {
        conf->cleanup_statuses = prev->cleanup_statuses;
    }

    ngx_conf_merge_ptr_value(conf->void_content_types, prev->void_content_types, NULL);

    ngx_conf_merge_str_value(conf->archive_elm_separator, prev->archive_elm_separator, "_");
    ngx_conf_merge_str_value(conf->archive_path_separator, prev->archive_path_separator, "!");

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_add_variables */
ngx_http_upload_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_upload_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_variable */
ngx_http_upload_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
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

static ngx_int_t /* {{{ ngx_http_upload_md5_variable */
ngx_http_upload_md5_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_uint_t             i;
    ngx_http_upload_ctx_t  *u;
    u_char                 *c;
    u_char                 *hex_table;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if(u->md5_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    hex_table = (u_char*)data;
    c = u->md5_ctx->md5_digest + MD5_DIGEST_LENGTH * 2;

    i = MD5_DIGEST_LENGTH;

    do{
        i--;
        *--c = hex_table[u->md5_ctx->md5_digest[i] & 0xf];
        *--c = hex_table[u->md5_ctx->md5_digest[i] >> 4];
    }while(i != 0);

    v->data = u->md5_ctx->md5_digest;
    v->len = MD5_DIGEST_LENGTH * 2;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_sha1_variable */
ngx_http_upload_sha1_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_uint_t             i;
    ngx_http_upload_ctx_t  *u;
    u_char                 *c;
    u_char                 *hex_table;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    if(u->sha1_ctx == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }

    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    hex_table = (u_char*)data;
    c = u->sha1_ctx->sha1_digest + SHA_DIGEST_LENGTH * 2;

    i = SHA_DIGEST_LENGTH;

    do{
        i--;
        *--c = hex_table[u->sha1_ctx->sha1_digest[i] & 0xf];
        *--c = hex_table[u->sha1_ctx->sha1_digest[i] >> 4];
    }while(i != 0);

    v->data = u->sha1_ctx->sha1_digest;
    v->len = SHA_DIGEST_LENGTH * 2;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_crc32_variable */
ngx_http_upload_crc32_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    uint32_t               *value;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (uint32_t *) ((char *) u + data);

    p = ngx_palloc(r->pool, NGX_INT_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%08uxd", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_http_upload_file_size_variable */
ngx_http_upload_file_size_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v,  uintptr_t data)
{
    ngx_http_upload_ctx_t  *u;
    u_char                 *p;
    off_t                  *value;

    u = ngx_http_get_module_ctx(r, ngx_http_upload_module);

    value = (off_t *) ((char *) u + data);

    p = ngx_palloc(r->pool, NGX_OFF_T_LEN);
    if (p == NULL) {
        return NGX_ERROR;
    }

    v->len = ngx_sprintf(p, "%O", *value) - p;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;
    v->data = p;

    return NGX_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_set_form_field */
ngx_http_upload_set_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_int_t                   n, i;
    ngx_str_t                  *value;
    ngx_http_script_compile_t   sc;
    ngx_http_upload_field_template_t *h;
    ngx_array_t                 **field;
    ngx_http_variable_t         *v;
    u_char                      *match;
    ngx_http_upload_loc_conf_t  *ulcf = conf;

    field = (ngx_array_t**) (((u_char*)conf) + cmd->offset);

    value = cf->args->elts;

    if (*field == NULL) {
        *field = ngx_array_create(cf->pool, 1,
                                  sizeof(ngx_http_upload_field_template_t));
        if (*field == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    h = ngx_array_push(*field);
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

    if (n > 0) {
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
    }

    /*
     * Compile field value
     */
    n = ngx_http_script_variables_count(&value[2]);

    if (n > 0) {
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
    }

    /*
     * Check for aggregate variables in script
     */
    for(i = 1;i <= 2;i++) {
        for (v = ngx_http_upload_aggregate_variables; v->name.len; v++) {
            match = ngx_strcasestrn(value[i].data, (char*)v->name.data, v->name.len - 1);

            /*
             * ngx_http_script_compile does check for final bracket earlier,
             * therefore we don't need to care about it, which simplifies things
             */
            if(match != NULL
                && ((match - value[i].data >= 1 && match[-1] == '$') 
                    || (match - value[i].data >= 2 && match[-2] == '$' && match[-1] == '{')))
            {
                if(cmd->offset != offsetof(ngx_http_upload_loc_conf_t, aggregate_field_templates)) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "variables upload_file_md5"
                                       ", upload_file_md5_uc"
                                       ", upload_file_sha1"
                                       ", upload_file_sha1_uc"
                                       ", upload_file_crc32"
                                       " and upload_file_size"
                                       " could be specified only in upload_aggregate_form_field directive");
                    return NGX_CONF_ERROR;
                }

                if(v->get_handler == ngx_http_upload_md5_variable)
                    ulcf->md5 = 1;

                if(v->get_handler == ngx_http_upload_sha1_variable)
                    ulcf->sha1 = 1;

                if(v->get_handler == ngx_http_upload_crc32_variable)
                    ulcf->crc32 = 1;
            }
        }
    }

    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_pass_form_field */
ngx_http_upload_pass_form_field(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf = conf;

    ngx_str_t                  *value;
#if (NGX_PCRE)
    ngx_int_t                   n;
    ngx_str_t                  err;
#endif
    ngx_http_upload_field_filter_t *f;

    value = cf->args->elts;

    if (ulcf->field_filters == NULL) {
        ulcf->field_filters = ngx_array_create(cf->pool, 1,
                                        sizeof(ngx_http_upload_field_filter_t));
        if (ulcf->field_filters == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    f = ngx_array_push(ulcf->field_filters);
    if (f == NULL) {
        return NGX_CONF_ERROR;
    }

#if (NGX_PCRE)
    f->regex = ngx_regex_compile(&value[1], 0, cf->pool, &err);

    if (f->regex == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "%s", err.data);
        return NGX_CONF_ERROR;
    }
    
    n = ngx_regex_capture_count(f->regex);

    if (n < 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           ngx_regex_capture_count_n " failed for "
                           "pattern \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    f->ncaptures = n;
#else
    f->text.len = value[1].len;
    f->text.data = value[1].data;
#endif

    return NGX_CONF_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_cleanup */
ngx_http_upload_cleanup(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf = conf;

    ngx_str_t                  *value;
    ngx_uint_t                 i;
    ngx_int_t                  status, lo, hi;
    uint16_t                   *s;

    value = cf->args->elts;

    if (ulcf->cleanup_statuses == NULL) {
        ulcf->cleanup_statuses = ngx_array_create(cf->pool, 1,
                                        sizeof(uint16_t));
        if (ulcf->cleanup_statuses == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    for (i = 1; i < cf->args->nelts; i++) {
        if(value[i].len > 4 && value[i].data[3] == '-') {
            lo = ngx_atoi(value[i].data, 3);

            if (lo == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid lower bound \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            hi = ngx_atoi(value[i].data + 4, value[i].len - 4);

            if (hi == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid upper bound \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            if (hi < lo) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "upper bound must be greater then lower bound in \"%V\"",
                                   &value[i]);
                return NGX_CONF_ERROR;
            }

        }else{
            status = ngx_atoi(value[i].data, value[i].len);

            if (status == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid value \"%V\"", &value[i]);
                return NGX_CONF_ERROR;
            }

            hi = lo = status;
        }

        if (lo < 400 || hi > 599) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "value(s) \"%V\" must be between 400 and 599",
                               &value[i]);
            return NGX_CONF_ERROR;
        }

        for(status = lo ; status <= hi; status++) {
            s = ngx_array_push(ulcf->cleanup_statuses);
            if (s == NULL) {
                return NGX_CONF_ERROR;
            }

            *s = status;
        }
    }


    return NGX_CONF_OK;
} /* }}} */

static ngx_uint_t /* {{{ ngx_http_upload_add_slave_conf */
ngx_http_upload_add_slave_conf(ngx_str_t *content_type, ngx_array_t **content_type_map,
    ngx_http_core_loc_conf_t *clcf, ngx_pool_t *pool)
{
    ngx_upload_content_type_map_t *ctmap;

    if(*content_type_map == NULL) {
        *content_type_map = ngx_array_create(pool, 2,
                                        sizeof(ngx_upload_content_type_map_t));
        if (*content_type_map == NULL) {
            return NGX_ERROR;
        }
    }

    ctmap = ngx_array_push(*content_type_map);
    if (ctmap == NULL) {
        return NGX_ERROR;
    }

    ctmap->content_type = *content_type;
    ctmap->conf = clcf;

    return NGX_OK;
} /* }}} */

ngx_int_t /* {{{ ngx_http_upload_add_filter */
ngx_http_upload_add_filter(ngx_http_upload_loc_conf_t *ulcf,
    ngx_upload_content_filter_t *cflt, ngx_pool_t *pool)
{
    ngx_upload_content_filter_t **pcflt;

    if(ulcf->content_filters == NULL) {
        ulcf->content_filters = ngx_array_create(pool, 2,
                                        sizeof(ngx_upload_content_filter_t*));
        if (ulcf->content_filters == NULL) {
            return NGX_ERROR;
        }
    }

    pcflt = ngx_array_push(ulcf->content_filters);
    if (pcflt == NULL) {
        return NGX_ERROR;
    }

    *pcflt = cflt;

    return NGX_OK;
} /* }}} */

static char * /* {{{ ngx_http_upload_filter_block */
ngx_http_upload_filter_block(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf, *pulcf = conf;

    char                      *rv;
    void                      *mconf;
    ngx_str_t                 *value;
    ngx_uint_t                 i;
    ngx_conf_t                 save;
    ngx_http_module_t         *module;
    ngx_http_conf_ctx_t       *ctx, *pctx;
    ngx_http_core_loc_conf_t  *clcf, *pclcf;

    value = cf->args->elts;

    ctx = ngx_pcalloc(cf->pool, sizeof(ngx_http_conf_ctx_t));
    if (ctx == NULL) {
        return NGX_CONF_ERROR;
    }

    pctx = cf->ctx;
    ctx->main_conf = pctx->main_conf;
    ctx->srv_conf = pctx->srv_conf;

    ctx->loc_conf = ngx_pcalloc(cf->pool, sizeof(void *) * ngx_http_max_module);
    if (ctx->loc_conf == NULL) {
        return NGX_CONF_ERROR;
    }

    for (i = 0; ngx_modules[i]; i++) {
        if (ngx_modules[i]->type != NGX_HTTP_MODULE) {
            continue;
        }

        module = ngx_modules[i]->ctx;

        if (module->create_loc_conf) {

            mconf = module->create_loc_conf(cf);
            if (mconf == NULL) {
                 return NGX_CONF_ERROR;
            }

            ctx->loc_conf[ngx_modules[i]->ctx_index] = mconf;
        }
    }

    ulcf = ctx->loc_conf[ngx_http_upload_module.ctx_index];

    ulcf->parent = pulcf;

    pclcf = pctx->loc_conf[ngx_http_core_module.ctx_index];

    clcf = ctx->loc_conf[ngx_http_core_module.ctx_index];
    clcf->loc_conf = ctx->loc_conf;
    clcf->name = pclcf->name;
    clcf->noname = 1;

    for (i = 1; i < cf->args->nelts; i++) {
        if(ngx_http_upload_add_slave_conf(&value[i], &pulcf->content_type_map,
            clcf, cf->pool) != NGX_OK) 
        {
            return NGX_CONF_ERROR;
        }
    }

    if (ngx_http_add_location(cf, &pclcf->locations, clcf) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->ctx = ctx;
    cf->cmd_type = NGX_HTTP_LOC_CONF;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    return rv;
} /* }}} */

static char * /* {{{ ngx_http_upload_pass */
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

ngx_upload_field_filter_t* /* {{{ ngx_upload_get_next_field_filter */
ngx_upload_get_next_field_filter(ngx_http_upload_ctx_t *ctx) {
    return &ngx_write_field_filter;
} /* }}} */

ngx_upload_content_filter_t* /* {{{ ngx_upload_get_next_content_filter */
ngx_upload_get_next_content_filter(ngx_http_upload_ctx_t *ctx) {
    ngx_upload_content_filter_t **cflt;

    if(ctx->current_content_filter_chain == NULL
        || ctx->current_content_filter_idx >= ctx->current_content_filter_chain->nelts)
    {
        return &ngx_write_content_filter;
    }

    cflt = ctx->current_content_filter_chain->elts;

    cflt += ctx->current_content_filter_idx;

    ctx->current_content_filter_idx++; 

    return *cflt;
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

        if (rb->rest <= (off_t) (b->end - b->last)) {

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

    if (rb->rest < (ssize_t) size) {
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
                    case NGX_UPLOAD_TOOLARGE:
                        return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
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

            if ((off_t)size > rb->rest) {
                size = (size_t)rb->rest;
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
        case NGX_UPLOAD_TOOLARGE:
            return NGX_HTTP_REQUEST_ENTITY_TOO_LARGE;
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
            upload_ctx->file_name.data = ngx_palloc(upload_ctx->request->pool, upload_ctx->file_name.len + 1);
            
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
                                   "malformed fieldname in part header");
                    return NGX_UPLOAD_MALFORMED;
                }

                upload_ctx->field_name.len = fieldname_end - fieldname_start;
                upload_ctx->field_name.data = ngx_pcalloc(upload_ctx->request->pool, upload_ctx->field_name.len + 1);

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

        upload_ctx->content_type.data = ngx_pcalloc(upload_ctx->request->pool, upload_ctx->content_type.len + 1);
        
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

ngx_int_t /* {{{ ngx_upload_set_exten */
ngx_upload_set_exten(ngx_http_upload_ctx_t *u, ngx_str_t *file_name, ngx_str_t *exten)
{
    ngx_int_t  i;

    exten->len = 0;
    exten->data = NULL;

    for (i = file_name->len - 1; i > 1; i--) {
        if (file_name->data[i] == '.' && file_name->data[i - 1] != '/') {

            exten->len = file_name->len - i - 1;
            exten->data = &file_name->data[i + 1];

            break;

        } else if (file_name->data[i] == '/') {
            break;
        }
    }

    return NGX_OK;
} /* }}} */

ngx_int_t /* {{{ ngx_upload_is_void_content_type */
ngx_upload_is_void_content_type(ngx_http_upload_ctx_t *u, ngx_str_t *content_type)
{
    ngx_http_upload_loc_conf_t  *ulcf;
    ngx_str_t                   *ct;
    ngx_uint_t                   i;

    ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

    if (ulcf->void_content_types != NULL) {

        ct = ulcf->void_content_types->elts;
        for (i = 0; i < ulcf->void_content_types->nelts; i++) {
            if(!ngx_strncasecmp(content_type->data, ct[i].data, ct[i].len)) {
                return NGX_OK;
            }
        }
    }

    return NGX_DECLINED;
} /* }}} */

ngx_int_t /* {{{ ngx_upload_resolve_content_type */
ngx_upload_resolve_content_type(ngx_http_upload_ctx_t *u, ngx_str_t *exten, ngx_str_t *content_type)
{
    u_char                     c, *p, *_exten;
    ngx_str_t                 *type;
    ngx_uint_t                 i, hash;
    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_get_module_loc_conf(u->request, ngx_http_core_module);

    if (exten->len) {

        hash = 0;

        for (i = 0; i < exten->len; i++) {
            c = exten->data[i];

            if (c >= 'A' && c <= 'Z') {

                p = ngx_palloc(u->request->pool, exten->len);
                if (p == NULL) {
                    return NGX_HTTP_INTERNAL_SERVER_ERROR;
                }

                hash = 0;
                _exten = p;

                for (i = 0; i < exten->len; i++) {
                    c = ngx_tolower(exten->data[i]);
                    hash = ngx_hash(hash, c);
                    *p++ = c;
                }

                exten->data = _exten;

                break;
            }

            hash = ngx_hash(hash, c);
        }

        type = ngx_hash_find(&clcf->types_hash, hash,
                             exten->data, exten->len);

        if (type) {
            *content_type = *type;

            return NGX_OK;
        }
    }

    /*
     * Content type defaults to text/plain according to rfc 2388
     */
    content_type->len = sizeof("text/plain") - 1;
    content_type->data = (u_char*)"text/plain";

    return NGX_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_upload_set_content_filter */
ngx_upload_set_content_filter(ngx_http_upload_ctx_t *u, ngx_str_t *content_type)
{
    ngx_uint_t                  i;
    ngx_http_upload_loc_conf_t  *pulcf, *ulcf;
    ngx_upload_content_type_map_t  *ulctm;

    pulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

    if(pulcf->parent) {
        pulcf = pulcf->parent;
    }

    u->current_content_filter_idx = 0;

    if (content_type->len && pulcf->content_type_map != NULL) {
        ulctm = pulcf->content_type_map->elts;
        for (i = 0; i < pulcf->content_type_map->nelts; i++) {

            if(ngx_strncasecmp(ulctm[i].content_type.data, content_type->data, content_type->len) == 0) {
                /*
                 * Got to slave configuration
                 */
                u->request->loc_conf = ulctm[i].conf->loc_conf;

                ulcf = ngx_http_get_module_loc_conf(u->request, ngx_http_upload_module);

                u->current_content_filter_chain = ulcf->content_filters;
                return NGX_OK;
            }
        }
    }

    u->current_content_filter_chain = pulcf->content_filters;

    return NGX_OK;
} /* }}} */

static ngx_int_t upload_start_part(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    ngx_str_t                 exten, content_type = ngx_null_string;
    ngx_upload_content_filter_t*  cflt;
    ngx_upload_field_filter_t*  fflt;

    if(upload_ctx->is_file) {
        upload_ctx->archive_path.data = NULL;
        upload_ctx->archive_path.len = 0;

        if(upload_ctx->content_type.len == 0 ||
            ngx_upload_is_void_content_type(upload_ctx, &upload_ctx->content_type) == NGX_OK) {

            ngx_upload_set_exten(upload_ctx, &upload_ctx->file_name, &exten);

            ngx_upload_resolve_content_type(upload_ctx, &exten, &content_type);

            upload_ctx->content_type = content_type;
        }

        upload_ctx->original_loc_conf = upload_ctx->request->loc_conf;

        ngx_upload_set_content_filter(upload_ctx, &upload_ctx->content_type);

        cflt = ngx_upload_get_next_content_filter(upload_ctx);

        upload_ctx->start_part_f = cflt->start;
        upload_ctx->finish_part_f = cflt->finish;
        upload_ctx->abort_part_f = cflt->abort;
        upload_ctx->process_chain_f = cflt->process_chain;
    }
    else{
        fflt = ngx_upload_get_next_field_filter(upload_ctx);

        upload_ctx->start_part_f = fflt->start;
        upload_ctx->finish_part_f = fflt->finish;
        upload_ctx->abort_part_f = fflt->abort;
        upload_ctx->process_chain_f = fflt->process_chain;
    }

    // Call user-defined event handler
    if(upload_ctx->start_part_f)
        return upload_ctx->start_part_f(upload_ctx);
    else
        return NGX_OK;
} /* }}} */

static void upload_finish_part(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    // Call user-defined event handler
    if(upload_ctx->finish_part_f)
        upload_ctx->finish_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;

    upload_ctx->request->loc_conf = upload_ctx->original_loc_conf;
} /* }}} */

static void upload_abort_part(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    if(upload_ctx->abort_part_f)
        upload_ctx->abort_part_f(upload_ctx);

    upload_discard_part_attributes(upload_ctx);

    upload_ctx->discard_data = 0;

    upload_ctx->request->loc_conf = upload_ctx->original_loc_conf;
} /* }}} */

static void upload_flush_output_buffer(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
    ngx_chain_t chain = { upload_ctx->output_buffer, NULL };
    ngx_int_t rc;

    if(upload_ctx->output_buffer->pos > upload_ctx->output_buffer->start) {
        if(upload_ctx->process_chain_f) {
            upload_ctx->output_buffer->last = upload_ctx->output_buffer->pos;
            upload_ctx->output_buffer->pos = upload_ctx->output_buffer->start;

            rc = upload_ctx->process_chain_f(upload_ctx, &chain);

            if(rc != NGX_OK && rc != NGX_AGAIN) {
                upload_ctx->discard_data = 1;
            }
        }

        upload_ctx->output_buffer->pos = upload_ctx->output_buffer->start;	
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
} /* }}} */

static void upload_shutdown_ctx(ngx_http_upload_ctx_t *upload_ctx) { /* {{{ */
	if(upload_ctx != 0) {
        // Abort file if we still processing it
        if(upload_ctx->state == upload_state_data) {
            upload_flush_output_buffer(upload_ctx);
            upload_abort_part(upload_ctx);
        }

        upload_discard_part_attributes(upload_ctx);
	}
} /* }}} */

static ngx_int_t upload_start(ngx_http_upload_ctx_t *upload_ctx, ngx_http_upload_loc_conf_t *ulcf) { /* {{{ */
	if(upload_ctx == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator = ngx_pcalloc(upload_ctx->request->pool, ulcf->max_header_len + 1);

	if(upload_ctx->header_accumulator == NULL)
		return NGX_ERROR;

	upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;
	upload_ctx->header_accumulator_end = upload_ctx->header_accumulator + ulcf->max_header_len;

	upload_ctx->output_buffer = ngx_create_temp_buf(upload_ctx->request->pool, ulcf->buffer_size);

	if(upload_ctx->output_buffer == NULL)
		return NGX_ERROR;

    upload_ctx->header_accumulator_pos = upload_ctx->header_accumulator;

    upload_ctx->first_part = 1;

	return NGX_OK;
} /* }}} */

static ngx_int_t upload_parse_content_type(ngx_http_upload_ctx_t *upload_ctx, ngx_str_t *content_type) { /* {{{ */
    // Find colon in content type string, which terminates mime type
    u_char *mime_type_end_ptr = (u_char*) ngx_strchr(content_type->data, ';');
    u_char *boundary_start_ptr, *boundary_end_ptr;

    upload_ctx->boundary.data = 0;

    if(mime_type_end_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED;
    }

    if(ngx_strncasecmp(content_type->data, (u_char*) MULTIPART_FORM_DATA_STRING,
        sizeof(MULTIPART_FORM_DATA_STRING) - 1)) {
        ngx_log_debug1(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "Content-Type is not multipart/form-data: %V", content_type);
        return NGX_UPLOAD_MALFORMED;
    }

    boundary_start_ptr = ngx_strstrn(mime_type_end_ptr, BOUNDARY_STRING, sizeof(BOUNDARY_STRING) - 2);

    if(boundary_start_ptr == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "no boundary found in Content-Type");
        return NGX_UPLOAD_MALFORMED; // No boundary found
    }

    boundary_start_ptr += sizeof(BOUNDARY_STRING) - 1;
    boundary_end_ptr = boundary_start_ptr + strcspn((char*)boundary_start_ptr, " ;\n\r");

    if(boundary_end_ptr == boundary_start_ptr) {
        ngx_log_debug0(NGX_LOG_DEBUG_CORE, upload_ctx->log, 0,
                       "boundary is empty");
        return NGX_UPLOAD_MALFORMED;
    }

    // Allocate memory for entire boundary plus \r\n-- plus terminating character
    upload_ctx->boundary.len = boundary_end_ptr - boundary_start_ptr + 4;
    upload_ctx->boundary.data = ngx_palloc(upload_ctx->request->pool, upload_ctx->boundary.len + 1);

    if(upload_ctx->boundary.data == NULL)
        return NGX_UPLOAD_NOMEM;

    ngx_cpystrn(upload_ctx->boundary.data + 4, boundary_start_ptr,
        boundary_end_ptr - boundary_start_ptr + 1);
    
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

static void upload_putc(ngx_http_upload_ctx_t *upload_ctx, u_char c) { /* {{{ */
    if(!upload_ctx->discard_data) {
        *upload_ctx->output_buffer->pos++ = c;

        if(upload_ctx->output_buffer->pos == upload_ctx->output_buffer->end)
            upload_flush_output_buffer(upload_ctx);	
    }
} /* }}} */

static ngx_int_t upload_process_buf(ngx_http_upload_ctx_t *upload_ctx, u_char *start, u_char *end) { /* {{{ */

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

                            rc = upload_start_part(upload_ctx);
                            
                            if(rc != NGX_OK) {
                                upload_ctx->state = upload_state_finish;
                                return rc; // User requested to cancel processing
                            } else {
                                upload_ctx->state = upload_state_data;
                                upload_ctx->output_buffer->pos = upload_ctx->output_buffer->start;	
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
                        upload_finish_part(upload_ctx);
                    else
                        upload_abort_part(upload_ctx);
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

static void /* {{{ ngx_upload_cleanup_handler */
ngx_upload_cleanup_handler(void *data)
{
    ngx_upload_cleanup_t        *cln = data;
    ngx_uint_t                  i;
    uint16_t                    *s;
    u_char                      do_cleanup = 0;

    if(!cln->aborted) {
        if(cln->fd >= 0) {
            if (ngx_close_file(cln->fd) == NGX_FILE_ERROR) {
                ngx_log_error(NGX_LOG_ALERT, cln->log, ngx_errno,
                              ngx_close_file_n " \"%s\" failed", cln->filename);
            }
        }

        if(cln->cleanup_statuses != NULL) {
            s = cln->cleanup_statuses->elts;

            for(i = 0; i < cln->cleanup_statuses->nelts; i++) {
                if(cln->headers_out->status == s[i]) {
                    do_cleanup = 1;
                }
            }
        }

        if(do_cleanup) {
                if(ngx_delete_file(cln->filename) == NGX_FILE_ERROR) { 
                    ngx_log_error(NGX_LOG_ERR, cln->log, ngx_errno
                        , "failed to remove destination file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
                }else
                    ngx_log_error(NGX_LOG_INFO, cln->log, 0
                        , "finished cleanup of file \"%s\" after http status %l"
                        , cln->filename
                        , cln->headers_out->status
                        );
        }
    }
} /* }}} */

