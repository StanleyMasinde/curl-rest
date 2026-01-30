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
        "GET" => curl_rest::Verb::Get,
        "POST" => curl_rest::Verb::Post,
        "PUT" => curl_rest::Verb::Put,
        "DELETE" => curl_rest::Verb::Delete,
        "HEAD" => curl_rest::Verb::Head,
        "OPTIONS" => curl_rest::Verb::Options,
        "PATCH" => curl_rest::Verb::Patch,
        "CONNECT" => curl_rest::Verb::Connect,
        "TRACE" => curl_rest::Verb::Trace,
        _ => {
            eprintln!("unsupported verb: {verb}");
            std::process::exit(2);
        }
    };

    let resp = curl_rest::Curl::default()
        .verb(verb)
        .send(&url)
        .expect("request failed");
    eprintln!("Status: {}", resp.status);
    println!("{}", String::from_utf8_lossy(&resp.body));
}
