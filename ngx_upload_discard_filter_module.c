/*
 * Copyright (C) 2008 Valery Kholodkov
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <ngx_http_upload.h>

static ngx_int_t ngx_upload_discard_start_handler(ngx_http_upload_ctx_t *u);
static void ngx_upload_discard_finish_handler(ngx_http_upload_ctx_t *u);
static void ngx_upload_discard_abort_handler(ngx_http_upload_ctx_t *u);
static ngx_int_t ngx_upload_discard_data_handler(ngx_http_upload_ctx_t *u,
    ngx_chain_t *chain);

static char *ngx_upload_discard_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_upload_content_filter_t /* {{{ */
ngx_upload_discard_content_filter = {
    ngx_upload_discard_start_handler,
    ngx_upload_discard_finish_handler,
    ngx_upload_discard_abort_handler,
    ngx_upload_discard_data_handler
} /* }}} */;

static ngx_command_t  ngx_upload_discard_filter_commands[] = { /* {{{ */

    /*
     * Discards uploaded file
     */
    { ngx_string("upload_discard"),
      NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
      ngx_upload_discard_command,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
}; /* }}} */

ngx_http_module_t  ngx_upload_discard_filter_module_ctx = { /* {{{ */
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    NULL,                                  /* create location configuration */
    NULL                                   /* merge location configuration */
}; /* }}} */

ngx_module_t  ngx_upload_discard_filter_module = { /* {{{ */
    NGX_MODULE_V1,
    &ngx_upload_discard_filter_module_ctx,   /* module context */
    ngx_upload_discard_filter_commands,      /* module directives */
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

static char * /* {{{ ngx_upload_discard_command */
ngx_upload_discard_command(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_upload_loc_conf_t *ulcf;

    ulcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_upload_module);

    if(ngx_http_upload_add_filter(ulcf, &ngx_upload_discard_content_filter, cf->pool) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* }}} */

static ngx_int_t /* {{{ ngx_upload_discard_start_handler */
ngx_upload_discard_start_handler(ngx_http_upload_ctx_t *u) {
    return NGX_OK;
} /* }}} */

static void /* {{{ ngx_upload_discard_finish_handler */
ngx_upload_discard_finish_handler(ngx_http_upload_ctx_t *u) {
} /* }}} */

static void /* {{{ ngx_upload_discard_abort_handler */
ngx_upload_discard_abort_handler(ngx_http_upload_ctx_t *u) {
} /* }}} */

static ngx_int_t /* {{{ ngx_upload_discard_data_handler */
ngx_upload_discard_data_handler(ngx_http_upload_ctx_t *u, ngx_chain_t *chain) {
    return NGX_OK;
} /* }}} */

