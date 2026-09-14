use thiserror::Error;

/// Error type returned by the curl-rest client.
#[derive(Debug, Error)]
pub enum Error {
    /// Error reported by libcurl.
    #[error("curl error: {0}")]
    Client(#[from] curl::Error),
    /// The provided URL could not be parsed.
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    /// The provided header value contained invalid characters.
    #[error("invalid header value for {0}")]
    InvalidHeaderValue(String),
    /// The provided header name contained invalid characters.
    #[error("invalid header name: {0}")]
    InvalidHeaderName(String),
    /// The server returned an unrecognized HTTP status code.
    #[error("invalid HTTP status code: {0}")]
    InvalidStatusCode(u32),
    /// There was an error during brotli decompression
    #[error("brotli decompression failed: {0}")]
    BrotliDecompression(#[from] std::io::Error),
}
