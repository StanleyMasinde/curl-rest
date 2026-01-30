# curl-rest

A Reqwest-like REST client built on libcurl for true blocking requests.

## Install
```sh 
cargo add curl-rest
```

Or manually

```toml
[dependencies]
curl-rest = "0.1"
```

### libcurl dependency

`curl-rest` is backed by libcurl, so your build will need a libcurl development package available on the system (for example, installed via your OS package manager). If you prefer a vendored build or static linking, enable the appropriate `curl`/`curl-sys` features in your application so Cargo propagates them to this crate.

This crate exposes a few convenience features (default is `ssl`):

- `ssl`: enable OpenSSL-backed TLS (libcurl's default).
- `rustls`: enable Rustls-backed TLS (disable default features in your dependency to avoid OpenSSL).
- `static-curl`: build and link against a bundled libcurl.
- `static-ssl`: build and link against a bundled OpenSSL.
- `vendored`: enables both `static-curl` and `static-ssl`.

## Usage

```rust
let resp = curl_rest::Curl::default()
    .get()
    .header(curl_rest::Header::Accept("application/json".into()))
    .query_param_kv("page", "1")
    .send("https://example.com/api/users")
    .expect("request failed");

println!("Status: {}", resp.status);
println!("{}", String::from_utf8_lossy(&resp.body));
```

### Default User-Agent

```rust
let resp = curl_rest::Curl::with_user_agent("my-app/1.0")
    .get()
    .header(curl_rest::Header::Accept("application/json".into()))
    .send("https://example.com/api/users")?;
// Ok::<(), curl_rest::Error>(())
```

If you set a `User-Agent` header explicitly, it overrides the default.

### Headers

```rust
let resp = curl_rest::Curl::default()
    .get()
    .header(curl_rest::Header::Authorization("Bearer token".into()))
    .header(curl_rest::Header::Accept("application/json".into()))
    .header(curl_rest::Header::Custom(
        "X-Request-Id".into(),
        "req-12345".into(),
    ))
    .send("https://example.com/private")?;
// Ok::<(), curl_rest::Error>(())
```

### Query params

```rust
let resp = curl_rest::Curl::default()
    .get()
    .query_param_kv("q", "rust")
    .query_param_kv("page", "2")
    .send("https://example.com/search")?;
// Ok::<(), curl_rest::Error>(())
```

### JSON body

```rust
let resp = curl_rest::Curl::default()
    .post()
    .body_json(r#"{"name":"stanley"}"#)
    .send("https://example.com/users")?;
// Ok::<(), curl_rest::Error>(())
```

## Examples

```sh
cargo run --example curl -- GET https://example.com
TOKEN=secret cargo run --example headers -- https://example.com/private
```

## Benchmarks

```sh
cargo bench
```

## License

MIT
