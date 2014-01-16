# NGINX HTTP Footer If Filter Module

## Introduction

The `ngx_http_footer_if_filter_module` is used to add given content to the end of the response according to the condition specified.

## Synopsis

```nginx

    location / {
        footer_if ($request_method == 'FOO') $arg_foo;
        root html;
    }
```

## Directives

* **syntax**: *footer_if (condition) $footer*
* **default**: --
* **context**: http, server, location

The specified `condition` is evaluated. If true, the value of `$footer` variable would be added to the end of the response. The syntax of condition is the same as it in the `if` directive in `rewrite` module.


## Installation

```shell
    cd nginx-**version**
    ./configure --add-module=/path/to/this/directory
    make
    make install
```

## Status

This module is compatible with following nginx releases:
- 1.2.6
- 1.2.7

Others are not tested.

## Author

FengGu <flygoast@126.com>
