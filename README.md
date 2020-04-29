ngx_ssl_trace_module
====================

A nginx module to setup categories for
[OpenSSL Tracing API](https://www.openssl.org/docs/manmaster/man3/OSSL_TRACE.html)

Note: OpenSSL must be configured with `enable-trace`.

```console
$ cd /path/to/openssl
$ ./config enable-trace
$ make
$ sudo make install
```

nginx config example

```text
...(snip)...

load_module modules/ngx_ssl_trace_module.so;
error_log  logs/error.log  warn;
events {
    worker_connections  1024;
}
ssl_trace_categories TLS,TLS_CIPHER;

...(snip)...
```
