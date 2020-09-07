cgit-gogs-auth-filter
=====================

[CGit](https://git.zx2c4.com/cgit/) `auth-filter` based on [Gogs](https://gogs.io/) authentication.

Requirements
------------

- `Rust` - The Rust Language, `Version >= 1.31`, [How to Install?](https://www.rust-lang.org/tools/install)

Building
--------

```sh
# Build with release profile
cargo build --release
# Install binary to /usr/local/bin/
sudo cp target/release/cgit-gogs-auth-filter /usr/local/bin/
```

Enable the filter
-----------------

To enable the filter with cgit, you have to set the `auth-filter` to the executable in `/etc/cgitrc`:

```ini
# Use cgit-gogs-auth-filter as auth-filter
auth-filter=/usr/local/bin/cgit-gogs-auth-filter
```

Configrations
-------------

The filter read the configurations from `/etc/cgitrc`, available settings:

```ini
# Directory to save the cookies
cgit-gogs-auth-filter.cache-dir=/var/cache/cgit-gogs-auth-filter
# Time to live of the cookies in seconds
cgit-gogs-auth-filter.cookie-ttl=7200
# Url for access to the gogs service.
cgit-gogs-auth-filter.gogs-url=http://127.0.0.1:3000
```

HTTP Basic authentication
-------------------------

To enable `HTTP Basic authentication`, you have to pass the `Authentication` Header with    `HTTP_AUTHORIZATION` environment variable.

For example in `nginx`:

```nginx
server {
    # ...
    location @cgit {
        # Pass the `Authorization` header with `HTTP_AUTHORIZATION`
        fastcgi_pass_header     Authorization;
    }
}
```

Auto cleanup expired cookies
----------------------------

The enable auto cleanup expired cookies, you should add a task to the `crontab` like this:

```crontab
# Cleanup cgit-gogs-auth-filter expired cookies at every minute
* * * * * /usr/local/bin/cgit-gogs-auth-filter expire
```
