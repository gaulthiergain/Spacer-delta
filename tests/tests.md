# Applications

| Unikernel & Sources | Description |
|--------------------|-------------|
| [Helloworld](https://github.com/unikraft/app-helloworld) | A simple “Hello World!” unikernel used for testing and demonstration purposes. |
| [Httpreply](https://github.com/unikraft/app-httpreply) | A minimal HTTP server, useful for testing basic web server functionality. |
| [Matrix-perf](https://github.com/gaulthiergain/apps/blob/main/matrix/main.c) | A parallel 2000×2000 matrix multiplier saving the result to a file. |
| [Nginx](https://github.com/unikraft/catalog/tree/main/library/nginx) | The Nginx web server ported as a unikernel. We modified it to stop just before the `accept()` function to simulate ephemeral unikernels. |
| [Proxy server](https://github.com/aarond10/https_dns_proxy) | A lightweight DNS-to-HTTPS proxy for the RFC 8484 DNS-over-HTTPS standard. |
| [SQLite](https://github.com/unikraft/catalog/tree/main/library/sqlite/3.40) | The SQLite shell ported as a unikernel. |

# Libraries (versioned)

| Library | Commits (oldest → latest) |
|--------|---------------------------|
| [lib-sqlite](https://github.com/unikraft/lib-sqlite) | 6b54e32, fc44ea1, 2c6d801, 1da038f, 9927df2, 8dbe27e, d87000c, 60d9e2a |
| [lib-pcre](https://github.com/gaulthiergain/lib-pcre) | 09fb6ce, 986d5c5, 1e0fcfc, 25c72e6, 2d6b260 |
| [lib-python](https://github.com/unikraft/lib-python3/) | a5f8ef1, 5900336, 04fad4f, dc93f53, 2d070a4 |
| [lib-nginx](https://github.com/unikraft/lib-nginx) | 0febe9a, 2eedb3f, 3229ec6, 6c5955f, 9cbe052 |
| [lib-pthread](https://github.com/unikraft/lib-pthread-embedded) | 49a2433, 2dd7129, 955a702, bf7c1f6, e2705f9d |