/*
 * Copyright (C) 2006, 2008 Valery Kholodkov
 */

#ifndef _NGX_HTTP_UPLOAD_H_INCLUDED_
#define _NGX_HTTP_UPLOAD_H_INCLUDED_

#if (NGX_HAVE_OPENSSL_MD5_H)
#include <openssl/md5.h>
#else
#include <md5.h>
#endif

#if (NGX_OPENSSL_MD5)
#define  MD5Init    MD5_Init
#define  MD5Update  MD5_Update
#define  MD5Final   MD5_Final
#endif

#if (NGX_HAVE_OPENSSL_SHA1_H)
#include <openssl/sha.h>
#else
#include <sha.h>
#endif

#define MULTIPART_FORM_DATA_STRING              "multipart/form-data"
#define BOUNDARY_STRING                         "boundary="
#define CONTENT_DISPOSITION_STRING              "Content-Disposition:"
#define CONTENT_TYPE_STRING                     "Content-Type:"
#define FORM_DATA_STRING                        "form-data"
#define ATTACHMENT_STRING                       "attachment"
#define FILENAME_STRING                         "filename=\""
#define FIELDNAME_STRING                        "name=\""

#define NGX_UPLOAD_SUBMODULE    0x444c5055 // UPLD

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
    ngx_table_elt_t         value;
    ngx_array_t             *field_lengths;
    ngx_array_t             *field_values;
    ngx_array_t             *value_lengths;
    ngx_array_t             *value_values;
} ngx_http_upload_field_template_t;

/*
 * Filter for fields in output form
 */
typedef struct {
#if (NGX_PCRE)
    ngx_regex_t              *regex;
    ngx_int_t                ncaptures;
#else
    ngx_str_t                text;
#endif
} ngx_http_upload_field_filter_t;

struct ngx_http_upload_ctx_s;

/*
 * Filter for content of certain type
 */
typedef struct {
    ngx_int_t (*start)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*finish)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*abort)(struct ngx_http_upload_ctx_s *upload_ctx);
	ngx_int_t (*process_chain)(struct ngx_http_upload_ctx_s *upload_ctx, ngx_chain_t *chain);
} ngx_upload_content_filter_t;

typedef ngx_upload_content_filter_t ngx_upload_field_filter_t;

/*
 * Mapping of a content type to slave location config
 */
struct ngx_http_upload_loc_conf_s;

typedef struct {
    ngx_str_t                           content_type;
    struct ngx_http_upload_loc_conf_s   *conf;
} ngx_upload_content_type_map_t;

/*
 * Upload cleanup record
 */
typedef struct ngx_http_upload_cleanup_s {
    ngx_fd_t                         fd;
    u_char                           *filename;
    ngx_http_headers_out_t           *headers_out;
    ngx_array_t                      *cleanup_statuses;
    ngx_log_t                        *log;
    unsigned int                     aborted:1;
} ngx_upload_cleanup_t;

/*
 * Upload configuration for specific location
 */
typedef struct ngx_http_upload_loc_conf_s {
    struct ngx_http_upload_loc_conf_s *parent;

    ngx_str_t         url;
    ngx_path_t        *store_path;
    ngx_uint_t        store_access;
    size_t            buffer_size;
    size_t            max_header_len;
    ngx_array_t       *field_templates;
    ngx_array_t       *aggregate_field_templates;
    ngx_array_t       *field_filters;
    ngx_array_t       *cleanup_statuses;

    ngx_array_t       *content_filters;
    ngx_array_t       *content_type_map;

    ngx_str_t         archive_elm_separator;
    ngx_str_t         archive_path_separator;

    unsigned int      md5:1;
    unsigned int      sha1:1;
    unsigned int      crc32:1;
} ngx_http_upload_loc_conf_t;

typedef struct ngx_http_upload_md5_ctx_s {
    MD5_CTX     md5;
    u_char      md5_digest[MD5_DIGEST_LENGTH * 2];
} ngx_http_upload_md5_ctx_t;

typedef struct ngx_http_upload_sha1_ctx_s {
    SHA_CTX     sha1;
    u_char      sha1_digest[SHA_DIGEST_LENGTH * 2];
} ngx_http_upload_sha1_ctx_t;

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
    ngx_str_t           archive_elm;
    ngx_str_t           archive_path;

    ngx_buf_t           *output_buffer;

    ngx_int_t (*start_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*finish_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
    void (*abort_part_f)(struct ngx_http_upload_ctx_s *upload_ctx);
	ngx_int_t (*process_chain_f)(struct ngx_http_upload_ctx_s *upload_ctx, ngx_chain_t *chain);

    ngx_http_request_t  *request;
    ngx_log_t           *log;

    ngx_file_t          output_file;
    ngx_chain_t         *chain;
    ngx_chain_t         *last;
    ngx_chain_t         *checkpoint;
    size_t              output_body_len;

    ngx_pool_cleanup_t       *cln;

    ngx_http_upload_md5_ctx_t   *md5_ctx;    
    ngx_http_upload_sha1_ctx_t  *sha1_ctx;    
    uint32_t                    crc32;    

    ngx_array_t         *current_content_filter_chain;    
    ngx_uint_t          current_content_filter_idx;

    unsigned int        first_part:1;
    unsigned int        discard_data:1;
    unsigned int        is_file:1;
    unsigned int        calculate_crc32:1;
} ngx_http_upload_ctx_t;

ngx_module_t  ngx_http_upload_module;

ngx_int_t ngx_upload_set_exten(ngx_http_upload_ctx_t *u, ngx_str_t *file_name, ngx_str_t *exten);
ngx_int_t ngx_upload_resolve_content_type(ngx_http_upload_ctx_t *u, ngx_str_t *exten, ngx_str_t *content_type);

#define ngx_upload_set_file_name(ctx, fn) \
    do{ \
        (ctx)->file_name.data = (fn)->data; \
        (ctx)->file_name.len = (fn)->len; \
    }while(0); \

#define ngx_upload_get_file_name(ctx, fn) \
    do{ \
        (fn)->data = (ctx)->file_name.data; \
        (fn)->len = (ctx)->file_name.len; \
    }while(0); \

#define ngx_upload_set_content_type(ctx, ct) \
    do{ \
        (ctx)->content_type.data = (ct)->data; \
        (ctx)->content_type.len = (ct)->len; \
    }while(0); \

#define ngx_upload_get_content_type(ctx, ct) \
    do{ \
        (ct)->data = (ctx)->content_type.data; \
        (ct)->len = (ctx)->content_type.len; \
    }while(0); \

#define ngx_upload_set_archive_elm(ctx, ae) \
    do{ \
        (ctx)->archive_elm.data = (ae)->data; \
        (ctx)->archive_elm.len = (ae)->len; \
    }while(0); \

#define ngx_upload_get_archive_elm(ctx, ae) \
    do{ \
        (ae)->data = (ctx)->archive_elm.data; \
        (ae)->len = (ctx)->archive_elm.len; \
    }while(0); \

#define ngx_upload_set_archive_path(ctx, ap) \
    do{ \
        (ctx)->archive_path.data = (ap)->data; \
        (ctx)->archive_path.len = (ap)->len; \
    }while(0); \

#define ngx_upload_get_archive_path(ctx, ap) \
    do{ \
        (ap)->data = (ctx)->archive_path.data; \
        (ap)->len = (ctx)->archive_path.len; \
    }while(0); \

ngx_upload_field_filter_t*
ngx_upload_get_next_field_filter(ngx_http_upload_ctx_t *ctx);

ngx_upload_content_filter_t*
ngx_upload_get_next_content_filter(ngx_http_upload_ctx_t *ctx);

ngx_int_t
ngx_http_upload_add_filter(ngx_http_upload_loc_conf_t *ulcf,
    ngx_upload_content_filter_t *cflt, ngx_pool_t *pool);

#endif //_NGX_HTTP_UPLOAD_H_INCLUDED_

