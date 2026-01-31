use std::env;

fn main() {
    let url = env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: cargo run --example headers -- <URL>");
        std::process::exit(2);
    });

    let token = env::var("TOKEN").unwrap_or_else(|_| {
        eprintln!("set TOKEN env var for Authorization header");
        std::process::exit(2);
    });

    let resp = curl_rest::Client::default()
        .get()
        .header(curl_rest::Header::Authorization(
            format!("Bearer {token}").into(),
        ))
        .header(curl_rest::Header::Accept("application/json".into()))
        .query_param_kv("include", "profile")
        .send(&url)
        .expect("request failed");

    eprintln!("Status: {}", resp.status);
    println!("{}", String::from_utf8_lossy(&resp.body));
}
