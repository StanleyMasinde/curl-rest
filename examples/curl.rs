use std::env;

fn main() {
    let mut args = env::args().skip(1);
    let verb = args.next().unwrap_or_else(|| {
        eprintln!("usage: cargo run --example curl -- <VERB> <URL>");
        std::process::exit(2);
    });
    let url = args.next().unwrap_or_else(|| {
        eprintln!("usage: cargo run --example curl -- <VERB> <URL>");
        std::process::exit(2);
    });

    let verb = match verb.to_uppercase().as_str() {
        "GET" => curl_rest::Method::Get,
        "POST" => curl_rest::Method::Post,
        "PUT" => curl_rest::Method::Put,
        "DELETE" => curl_rest::Method::Delete,
        "HEAD" => curl_rest::Method::Head,
        "OPTIONS" => curl_rest::Method::Options,
        "PATCH" => curl_rest::Method::Patch,
        "CONNECT" => curl_rest::Method::Connect,
        "TRACE" => curl_rest::Method::Trace,
        _ => {
            eprintln!("unsupported verb: {verb}");
            std::process::exit(2);
        }
    };

    let resp = curl_rest::Client::default()
        .method(verb)
        .send(&url)
        .expect("request failed");
    eprintln!("Status: {}", resp.status);
    println!("{}", String::from_utf8_lossy(&resp.body));
}
