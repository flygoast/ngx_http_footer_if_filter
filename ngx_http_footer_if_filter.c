/*
 * Copyright (c) 2014, FengGu <flygoast@126.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


static volatile ngx_cycle_t  *ngx_http_footer_if_filter_prev_cycle;


typedef struct {
    ngx_array_t  *codes;
    ngx_array_t  *lengths;
    ngx_array_t  *values;
    ngx_str_t     footer;
} ngx_http_footer_if_filter_condition_t;


typedef struct {
    ngx_array_t  *conditions;  /* ngx_http_footer_if_filter_condition_t */
} ngx_http_footer_if_filter_loc_conf_t;


typedef struct {
    unsigned  required:1;
} ngx_http_footer_if_filter_main_conf_t;


typedef struct {
    ngx_str_t  footer;
} ngx_http_footer_if_filter_ctx_t;


static char *ngx_http_footer_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_footer_if_filter_init(ngx_conf_t *cf);
static char *ngx_http_footer_if_condition(ngx_conf_t *cf,
    ngx_http_footer_if_filter_condition_t *condition);
static char *ngx_http_footer_if_condition_value(ngx_conf_t *cf,
    ngx_http_footer_if_filter_condition_t *condition, ngx_str_t *value);
static void *ngx_http_footer_if_filter_create_main_conf(ngx_conf_t *cf);
static void *ngx_http_footer_if_filter_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_footer_if_filter_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_footer_if_body_filter(ngx_http_request_t *r,
    ngx_chain_t *in);
static ngx_int_t ngx_http_footer_if_header_filter(ngx_http_request_t *r);


static ngx_command_t  ngx_http_footer_if_filter_commands[] = {

    { ngx_string("footer_if"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_2MORE,
      ngx_http_footer_if,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_footer_if_filter_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_footer_if_filter_init,         /* postconfiguration */

    ngx_http_footer_if_filter_create_main_conf,
                                            /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */

    ngx_http_footer_if_filter_create_loc_conf,
                                            /* create location configuration */
    ngx_http_footer_if_filter_merge_loc_conf,
                                            /* merge location configuration */
};


ngx_module_t  ngx_http_footer_if_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_footer_if_filter_module_ctx,  /* module context */
    ngx_http_footer_if_filter_commands,     /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt  ngx_http_next_body_filter;


static char *
ngx_http_footer_if(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                              *value;
    ngx_uint_t                              n;
    ngx_http_script_compile_t               sc;
    ngx_http_footer_if_filter_condition_t  *condition;
    ngx_http_footer_if_filter_main_conf_t  *fmcf;
    ngx_http_footer_if_filter_loc_conf_t   *flcf = conf;

    if (flcf->conditions == NULL) {
        flcf->conditions = ngx_array_create(cf->pool, 4,
                                 sizeof(ngx_http_footer_if_filter_condition_t));
        if (flcf->conditions == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    condition = ngx_array_push(flcf->conditions);
    if (condition == NULL) {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(condition, sizeof(ngx_http_footer_if_filter_condition_t));

    value = cf->args->elts;
    condition->footer = value[cf->args->nelts - 1];

    n = ngx_http_script_variables_count(&condition->footer);

    if (n) {
        ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

        sc.cf = cf;
        sc.source = &condition->footer;
        sc.lengths = &condition->lengths;
        sc.values = &condition->values;
        sc.variables = n;
        sc.complete_lengths = 1;
        sc.complete_values = 1;

        if (ngx_http_script_compile(&sc) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }

    cf->args->nelts--;

    if (ngx_http_footer_if_condition(cf, condition) != NGX_CONF_OK) {
        return NGX_CONF_ERROR;
    }

    fmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_footer_if_filter_module);
    fmcf->required = 1;

    return NGX_CONF_OK;
}


static char *
ngx_http_footer_if_condition(ngx_conf_t *cf,
    ngx_http_footer_if_filter_condition_t *condition)
{
    u_char                        *p;
    size_t                         len;
    ngx_str_t                     *value;
    ngx_uint_t                     cur, last;
    ngx_regex_compile_t            rc;
    ngx_http_script_code_pt       *code;
    ngx_http_script_file_code_t   *fop;
    ngx_http_script_regex_code_t  *regex;
    u_char                         errstr[NGX_MAX_CONF_ERRSTR];

    value = cf->args->elts;
    last = cf->args->nelts - 1;

    if (value[1].len < 1 || value[1].data[0] != '(') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (value[1].len == 1) {
        cur = 2;

    } else {
        cur = 1;
        value[1].len--;
        value[1].data++;
    }

    if (value[last].len < 1 || value[last].data[value[last].len - 1] != ')') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[last]);
        return NGX_CONF_ERROR;
    }

    if (value[last].len == 1) {
        last--;

    } else {
        value[last].len--;
        value[last].data[value[last].len] = '\0';
    }

    len = value[cur].len;
    p = value[cur].data;

    if (len > 1 && p[0] == '$') {

        if (cur != last && cur + 2 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        if (ngx_http_footer_if_condition_value(cf, condition, &value[cur])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        if (cur == last) {
            goto end;
        }

        cur++;

        len = value[cur].len;
        p = value[cur].data;

        if (len == 1 && p[0] == '=') {
            if (ngx_http_footer_if_condition_value(cf, condition, &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &condition->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_equal_code;

            goto end;
        }

        if (len == 2 && p[0] == '!' && p[1] == '=') {

            if (ngx_http_footer_if_condition_value(cf, condition, &value[last])
                != NGX_CONF_OK)
            {
                return NGX_CONF_ERROR;
            }

            code = ngx_http_script_start_code(cf->pool, &condition->codes,
                                              sizeof(uintptr_t));
            if (code == NULL) {
                return NGX_CONF_ERROR;
            }

            *code = ngx_http_script_not_equal_code;
            goto end;
        }

        if ((len == 1 && p[0] == '~')
            || (len == 2 && p[0] == '~' && p[1] == '*')
            || (len == 2 && p[0] == '!' && p[1] == '~')
            || (len == 3 && p[0] == '!' && p[1] == '~' && p[2] == '*'))
        {
            regex = ngx_http_script_start_code(cf->pool, &condition->codes,
                                          sizeof(ngx_http_script_regex_code_t));
            if (regex == NULL) {
                return NGX_CONF_ERROR;
            }

            ngx_memzero(regex, sizeof(ngx_http_script_regex_code_t));
            
            ngx_memzero(&rc, sizeof(ngx_regex_compile_t));

            rc.pattern = value[last];
            rc.options = (p[len - 1] == '*') ? NGX_REGEX_CASELESS : 0;
            rc.err.len = NGX_MAX_CONF_ERRSTR;
            rc.err.data = errstr;

            regex->regex = ngx_http_regex_compile(cf, &rc);
            if (regex->regex == NULL) {
                return NGX_CONF_ERROR;
            }

            regex->code = ngx_http_script_regex_start_code;
            regex->next = sizeof(ngx_http_script_regex_code_t);
            regex->test = 1;
            if (p[0] == '!') {
                regex->negative_test = 1;
            }
            regex->name = value[last];

            goto end;
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unexpected \"%V\" in condition", &value[cur]);
        return NGX_CONF_ERROR;

    } else if ((len == 2 && p[0] == '-')
               || (len == 3 && p[0] == '!' && p[1] == '-'))
    {
        if (cur + 1 != last) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid condition \"%V\"", &value[cur]);
            return NGX_CONF_ERROR;
        }

        value[last].data[value[last].len] = '\0';
        value[last].len++;

        if (ngx_http_footer_if_condition_value(cf, condition, &value[last])
            != NGX_CONF_OK)
        {
            return NGX_CONF_ERROR;
        }

        fop = ngx_http_script_start_code(cf->pool, &condition->codes,
                                         sizeof(ngx_http_script_file_code_t));
        if (fop == NULL) {
            return NGX_CONF_ERROR;
        }

        fop->code = ngx_http_script_file_code;

        if (p[1] == 'f') {
            fop->op = ngx_http_script_file_plain;
            goto end;
        }

        if (p[1] == 'd') {
            fop->op = ngx_http_script_file_dir;
            goto end;
        }

        if (p[1] == 'e') {
            fop->op = ngx_http_script_file_exists;
            goto end;
        }

        if (p[1] == 'x') {
            fop->op = ngx_http_script_file_exec;
            goto end;
        }

        if (p[0] == '!') {
            if (p[2] == 'f') {
                fop->op = ngx_http_script_file_not_plain;
                goto end;
            }

            if (p[2] == 'd') {
                fop->op = ngx_http_script_file_not_dir;
                goto end;
            }

            if (p[2] == 'e') {
                fop->op = ngx_http_script_file_not_exists;
                goto end;
            }

            if (p[2] == 'x') {
                fop->op = ngx_http_script_file_not_exec;
                goto end;
            }
        }

        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid condition \"%V\"", &value[cur]);
        return NGX_CONF_ERROR;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid condition \"%V\"", &value[cur]);

    return NGX_CONF_ERROR;

end:

    code = ngx_array_push_n(condition->codes, sizeof(uintptr_t));
    if (code == NULL) {
        return NGX_CONF_ERROR;
    }

    *code = (uintptr_t) NULL;

    return NGX_CONF_OK;
}


static char *
ngx_http_footer_if_condition_value(ngx_conf_t *cf,
    ngx_http_footer_if_filter_condition_t *condition, ngx_str_t *value)
{
    ngx_int_t                              n;
    ngx_http_script_compile_t              sc;
    ngx_http_script_value_code_t          *val;
    ngx_http_script_complex_value_code_t  *complex;

    n = ngx_http_script_variables_count(value);

    if (n == 0) {
        val = ngx_http_script_start_code(cf->pool, &condition->codes,
                                         sizeof(ngx_http_script_value_code_t));
        if (val == NULL) {
            return NGX_CONF_ERROR;
        }

        n = ngx_atoi(value->data, value->len);

        if (n == NGX_ERROR) {
            n = 0;
        }

        val->code = ngx_http_script_value_code;
        val->value = (uintptr_t) n;
        val->text_len = (uintptr_t) value->len;
        val->text_data = (uintptr_t) value->data;

        return NGX_CONF_OK;
    }

    complex = ngx_http_script_start_code(cf->pool, &condition->codes,
                                  sizeof(ngx_http_script_complex_value_code_t));
    if (complex == NULL) {
        return NGX_CONF_ERROR;
    }

    complex->code = ngx_http_script_complex_value_code;
    complex->lengths = NULL;

    ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));

    sc.cf = cf;
    sc.source = value;
    sc.lengths = &complex->lengths;
    sc.values = &condition->codes;
    sc.variables = n;
    sc.complete_lengths = 1;

    if (ngx_http_script_compile(&sc) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_footer_if_filter_init(ngx_conf_t *cf)
{
    ngx_http_footer_if_filter_main_conf_t  *fmcf;
    ngx_flag_t                              multi_http_blocks;

    fmcf = ngx_http_conf_get_module_main_conf(cf,
                                              ngx_http_footer_if_filter_module);

    if (ngx_http_footer_if_filter_prev_cycle != ngx_cycle) {
        ngx_http_footer_if_filter_prev_cycle = ngx_cycle;
        multi_http_blocks = 0;

    } else {
        multi_http_blocks = 1;
    }

    if (multi_http_blocks || fmcf->required) {
        ngx_http_next_header_filter = ngx_http_top_header_filter;
        ngx_http_top_header_filter = ngx_http_footer_if_header_filter;

        ngx_http_next_body_filter = ngx_http_top_body_filter;
        ngx_http_top_body_filter = ngx_http_footer_if_body_filter;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_footer_if_header_filter(ngx_http_request_t *r)
{
    ngx_uint_t                              i;
    ngx_str_t                               footer;
    ngx_http_script_code_pt                 code;
    ngx_http_script_engine_t                e;
    ngx_http_variable_value_t               stack[10];
    ngx_http_footer_if_filter_ctx_t        *ctx;
    ngx_http_footer_if_filter_loc_conf_t   *flcf;
    ngx_http_footer_if_filter_condition_t  *conditions;

    flcf = ngx_http_get_module_loc_conf(r, ngx_http_footer_if_filter_module);

    if (r != r->main
        || (r->headers_out.status != NGX_HTTP_OK
            && r->headers_out.status != NGX_HTTP_CREATED
            && r->headers_out.status != NGX_HTTP_NO_CONTENT
            && r->headers_out.status != NGX_HTTP_PARTIAL_CONTENT
            && r->headers_out.status != NGX_HTTP_MOVED_PERMANENTLY
            && r->headers_out.status != NGX_HTTP_MOVED_TEMPORARILY
            && r->headers_out.status != NGX_HTTP_SEE_OTHER
            && r->headers_out.status != NGX_HTTP_NOT_MODIFIED
            && r->headers_out.status != NGX_HTTP_TEMPORARY_REDIRECT)
        || flcf->conditions == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    conditions = flcf->conditions->elts;
    for (i = 0; i < flcf->conditions->nelts; i++) {
        ngx_memzero(&e, sizeof(ngx_http_script_engine_t));
        ngx_memzero(&stack, sizeof(stack));

        e.sp = stack;
        e.ip = conditions[i].codes->elts;
        e.request = r;
        e.quote = 1;
        e.log = 1;
        e.status = NGX_DECLINED;

        while (*(uintptr_t *) e.ip) {
            code = *(ngx_http_script_code_pt *) e.ip;
            code(&e);
        }

        e.sp--;

        if (e.sp->len && (e.sp->len != 1 || e.sp->data[0] != '0')) {
            break;
        }
    }

    if (i == flcf->conditions->nelts) {
        return ngx_http_next_header_filter(r);
    }

    if (conditions[i].lengths) {
        if (ngx_http_script_run(r, &footer, conditions[i].lengths->elts, 0, 
                                conditions[i].values->elts)
            == NULL)
        {
            return NGX_ERROR;
        }

    } else {
        footer = conditions[i].footer;
    }

    if (footer.len == 0) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_footer_if_filter_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->footer = footer;

    ngx_http_set_ctx(r, ctx, ngx_http_footer_if_filter_module);

    if (r->headers_out.content_length_n != -1) {
        r->headers_out.content_length_n += ctx->footer.len;
    }

    if (r->headers_out.content_length) {
        r->headers_out.content_length->hash = 0;
        r->headers_out.content_length = NULL;
    }

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_footer_if_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_buf_t                        *buf;
    ngx_uint_t                        last;
    ngx_chain_t                      *cl, *nl;
    ngx_http_footer_if_filter_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_footer_if_filter_module);
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    last = 0;

    for (cl = in; cl; cl = cl->next) {
        if (cl->buf->last_buf) {
            last = 1;
            break;
        }
    }

    if (!last) {
        return ngx_http_next_body_filter(r, in);
    }

    buf = ngx_calloc_buf(r->pool);
    if (buf == NULL) {
        return NGX_ERROR;
    }

    buf->pos = ctx->footer.data;
    buf->last = buf->pos + ctx->footer.len;
    buf->start = buf->pos;
    buf->end = buf->last;
    buf->last_buf = 1;
    buf->memory = 1;

    if (ngx_buf_size(cl->buf) == 0) {
        cl->buf = buf;

    } else {
        nl = ngx_alloc_chain_link(r->pool);
        if (nl == NULL) {
            return NGX_ERROR;
        }

        nl->buf = buf;
        nl->next = NULL;
        cl->next = nl;
        cl->buf->last_buf = 0;
    }

    return ngx_http_next_body_filter(r, in);
}


static void *
ngx_http_footer_if_filter_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_footer_if_filter_main_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_footer_if_filter_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *     conf->required = 0;
     */
    
    return conf;
}


static void *
ngx_http_footer_if_filter_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_footer_if_filter_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool,
                       sizeof(ngx_http_footer_if_filter_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *     conf->conditions = NULL;
     */
    
    return conf;
}


static char *
ngx_http_footer_if_filter_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child)
{
    ngx_http_footer_if_filter_loc_conf_t  *prev = parent;
    ngx_http_footer_if_filter_loc_conf_t  *conf = child;

    if (conf->conditions == NULL && prev->conditions) {
        conf->conditions = prev->conditions;
    }

    return NGX_CONF_OK;
}
