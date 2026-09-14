use curl_rest::{Client, Header, Method, QueryParam};

#[test]
fn response_reexports_resolve_to_same_type() {
    fn accepts_root(_: curl_rest::Response) {}
    accepts_root(curl_rest::types::Response::default());

    fn accepts_root_header(_: curl_rest::ResponseHeader) {}
    accepts_root_header(curl_rest::types::ResponseHeader {
        name: "X-Test".to_string(),
        value: "ok".to_string(),
    });
}

#[test]
fn builder_chain_builds_without_network() {
    let _client = Client::default()
        .method(Method::Post)
        .headers([
            Header::Accept("application/json".into()),
            Header::UserAgent("curl-rest/0.1".into()),
        ])
        .query_params([
            QueryParam::new("sort", "desc"),
            QueryParam::new("limit", "50"),
        ])
        .max_redirects(5)
        .brotli(false)
        .body_text("hello");
}
