
/*
 * Copyright (C) Hiroaki Nakamura.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <openssl/bio.h>
#include <openssl/trace.h>


typedef struct {
    ngx_str_t  categories;
} ngx_ssl_trace_conf_t;


static void *ngx_ssl_trace_create_conf(ngx_cycle_t *cycle);
static char *ngx_ssl_trace_init_conf(ngx_cycle_t *cycle, void *conf);

static char *ngx_ssl_trace_categories(ngx_conf_t *cf, void *post, void *data);
static ngx_conf_post_t  ngx_ssl_trace_categories_post = { ngx_ssl_trace_categories };

static void setup_trace(const char *str);


static ngx_command_t  ngx_ssl_trace_commands[] = {

    { ngx_string("ssl_trace_categories"),
      NGX_MAIN_CONF|NGX_DIRECT_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      0,
      offsetof(ngx_ssl_trace_conf_t, categories),
      &ngx_ssl_trace_categories_post },

      ngx_null_command
};


static ngx_core_module_t  ngx_ssl_trace_module_ctx = {
    ngx_string("ssl_trace"),
    ngx_ssl_trace_create_conf,
    ngx_ssl_trace_init_conf
};


ngx_module_t  ngx_ssl_trace_module = {
    NGX_MODULE_V1,
    &ngx_ssl_trace_module_ctx,             /* module context */
    ngx_ssl_trace_commands,                /* module directives */
    NGX_CORE_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static void *
ngx_ssl_trace_create_conf(ngx_cycle_t *cycle)
{
    ngx_ssl_trace_conf_t  *stcf;

    stcf = ngx_pcalloc(cycle->pool, sizeof(ngx_ssl_trace_conf_t));
    if (stcf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->categories = { 0, NULL };
     */

    return stcf;
}


BIO *bio_err = NULL;

# define B_FORMAT_TEXT   0x8000
# define FORMAT_TEXT    (1 | B_FORMAT_TEXT)     /* Generic text */

int FMT_istext(int format)
{
    return (format & B_FORMAT_TEXT) == B_FORMAT_TEXT;
}

BIO *dup_bio_err(int format)
{
    BIO *b = BIO_new_fp(stderr,
                        BIO_NOCLOSE | (FMT_istext(format) ? BIO_FP_TEXT : 0));
#ifdef OPENSSL_SYS_VMS
    if (FMT_istext(format))
        b = BIO_push(BIO_new(BIO_f_linebuffer()), b);
#endif
    return b;
}

static char *
ngx_ssl_trace_init_conf(ngx_cycle_t *cycle, void *conf)
{
    ngx_ssl_trace_conf_t *stcf = conf;

    bio_err = dup_bio_err(FORMAT_TEXT);

    stcf->categories.len = 0;
    stcf->categories.data = NULL;

    return NGX_CONF_OK;
}


static char *
ngx_ssl_trace_categories(ngx_conf_t *cf, void *post, void *data)
{
    ngx_str_t  *categories = data;

    if (categories->len == 0) {
        return NGX_CONF_OK;
    }

    ngx_log_error(NGX_LOG_NOTICE, cf->log, 0, "ssl_trace_categories=%*s", categories->len, categories->data);
    setup_trace((const char *) categories->data);

    return NGX_CONF_OK;
}


typedef struct tracedata_st {
    BIO *bio;
    unsigned int ingroup:1;
} tracedata;

DEFINE_STACK_OF(tracedata)
static STACK_OF(tracedata) *trace_data_stack;

static void tracedata_free(tracedata *data)
{
    BIO_free_all(data->bio);
    OPENSSL_free(data);
}

static STACK_OF(tracedata) *trace_data_stack;

static void cleanup_trace(void)
{
    sk_tracedata_pop_free(trace_data_stack, tracedata_free);
}

static size_t internal_trace_cb(const char *buf, size_t cnt,
                                int category, int cmd, void *vdata)
{
    int ret = 0;
    tracedata *trace_data = vdata;
    char buffer[256], *hex;
    CRYPTO_THREAD_ID tid;

    switch (cmd) {
    case OSSL_TRACE_CTRL_BEGIN:
        if (trace_data->ingroup) {
            BIO_printf(bio_err, "ERROR: tracing already started\n");
            return 0;
        }
        trace_data->ingroup = 1;

        tid = CRYPTO_THREAD_get_current_id();
        hex = OPENSSL_buf2hexstr((const unsigned char *)&tid, sizeof(tid));
        BIO_snprintf(buffer, sizeof(buffer), "TRACE[%s]:%s: ",
                     hex == NULL ? "<null>" : hex,
                     OSSL_trace_get_category_name(category));
        OPENSSL_free(hex);
        BIO_set_prefix(trace_data->bio, buffer);
        break;
    case OSSL_TRACE_CTRL_WRITE:
        if (!trace_data->ingroup) {
            BIO_printf(bio_err, "ERROR: writing when tracing not started\n");
            return 0;
        }

        ret = BIO_write(trace_data->bio, buf, cnt);
        break;
    case OSSL_TRACE_CTRL_END:
        if (!trace_data->ingroup) {
            BIO_printf(bio_err, "ERROR: finishing when tracing not started\n");
            return 0;
        }
        trace_data->ingroup = 0;

        BIO_set_prefix(trace_data->bio, NULL);

        break;
    }

    return ret < 0 ? 0 : ret;
}

static void setup_trace_category(int category)
{
    BIO *channel;
    tracedata *trace_data;
    BIO *bio = NULL;

    if (OSSL_trace_enabled(category))
        return;

    bio = BIO_new(BIO_f_prefix());
    channel = BIO_push(bio, dup_bio_err(FORMAT_TEXT));
    trace_data = OPENSSL_zalloc(sizeof(*trace_data));

    if (trace_data == NULL
        || bio == NULL
        || (trace_data->bio = channel) == NULL
        || OSSL_trace_set_callback(category, internal_trace_cb,
                                   trace_data) == 0
        || sk_tracedata_push(trace_data_stack, trace_data) == 0) {

        fprintf(stderr,
                "warning: unable to setup trace callback for category '%s'.\n",
                OSSL_trace_get_category_name(category));

        OSSL_trace_set_callback(category, NULL, NULL);
        BIO_free_all(channel);
    }
}

static void setup_trace(const char *str)
{
    char *val;

    /*
     * We add this handler as early as possible to ensure it's executed
     * as late as possible, i.e. after the TRACE code has done its cleanup
     * (which happens last in OPENSSL_cleanup).
     */
    atexit(cleanup_trace);

    trace_data_stack = sk_tracedata_new_null();
    val = OPENSSL_strdup(str);

    if (val != NULL) {
        char *valp = val;
        char *item;

        for (valp = val; (item = strtok(valp, ",")) != NULL; valp = NULL) {
            int category = OSSL_trace_get_category_num(item);

            if (category == OSSL_TRACE_CATEGORY_ALL) {
                while (++category < OSSL_TRACE_CATEGORY_NUM)
                    setup_trace_category(category);
                break;
            } else if (category > 0) {
                setup_trace_category(category);
            } else {
                fprintf(stderr,
                        "warning: unknown trace category: '%s'.\n", item);
            }
        }
    }

    OPENSSL_free(val);
}
