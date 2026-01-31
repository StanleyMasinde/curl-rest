use criterion::{Criterion, criterion_group, criterion_main};
use std::hint::black_box;

fn builder_basic(c: &mut Criterion) {
    c.bench_function("builder_basic", |b| {
        b.iter(|| {
            let curl = curl_rest::Client::default()
                .get()
                .header(curl_rest::Header::Accept("application/json".into()))
                .header(curl_rest::Header::UserAgent("curl-rest/0.1".into()))
                .query_param_kv("page", "1")
                .query_param(curl_rest::QueryParam::new("q", "rust curl"))
                .body_json(r#"{"hello":"world"}"#);
            black_box(curl);
        })
    });
}

fn builder_many(c: &mut Criterion) {
    c.bench_function("builder_many", |b| {
        b.iter(|| {
            let curl = curl_rest::Client::default()
                .post()
                .headers([
                    curl_rest::Header::Accept("application/json".into()),
                    curl_rest::Header::AcceptLanguage("en-US".into()),
                    curl_rest::Header::CacheControl("no-cache".into()),
                ])
                .query_params([
                    curl_rest::QueryParam::new("sort", "desc"),
                    curl_rest::QueryParam::new("limit", "50"),
                    curl_rest::QueryParam::new("offset", "0"),
                ])
                .body_text("hello from curl-rest");
            black_box(curl);
        })
    });
}

criterion_group!(benches, builder_basic, builder_many);
criterion_main!(benches);
