//! A small, blocking REST client built on libcurl.
//!
<<<<<<< Updated upstream
//! The API is a builder centered around `Curl`, with GET as the default method.
=======
//! The API is a builder centered around `Client`, with GET as the default verb.
>>>>>>> Stashed changes
//! Use `send` as the terminal operation.
//!
//! # libcurl dependency
//! `curl-rest` links to libcurl, so your build needs a libcurl development
//! package available on the system (for example, installed via your OS package
//! manager). If you prefer a vendored build or static linking, enable the
//! appropriate `curl`/`curl-sys` features in your application so Cargo
//! propagates them to this crate.
//!
//! This crate exposes a few convenience features (default is `ssl`):
//! - `ssl`: enable OpenSSL-backed TLS (libcurl's default).
//! - `rustls`: enable Rustls-backed TLS (disable default features in your
//!   dependency to avoid OpenSSL).
//! - `static-curl`: build and link against a bundled libcurl.
//! - `static-ssl`: build and link against a bundled OpenSSL.
//! - `vendored`: enables both `static-curl` and `static-ssl`.
//!
//! # Quickstart
//! ```no_run
//! let resp = curl_rest::get("https://example.com")?;
//! println!("Status: {}", resp.status);
//!
//! let resp = curl_rest::Client::default()
//!     .post()
//!     .body_json(r#"{"name":"stanley"}"#)
//!     .send("https://example.com/users")?;
//! println!("{}", String::from_utf8_lossy(&resp.body));
//! # Ok::<(), curl_rest::Error>(())
//! ```
//!
//! # Examples
//! ```no_run
//! let resp = curl_rest::Client::default()
//!     .get()
//!     .header(curl_rest::Header::Accept("application/json".into()))
//!     .header(curl_rest::Header::Custom("X-Request-Id".into(), "req-123".into()))
//!     .query_param_kv("page", "1")
//!     .send("https://example.com/api/users")
//!     .expect("request failed");
//! println!("Status: {}", resp.status);
//! ```

use curl::easy::{Easy2, Handler, List, WriteError};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use std::borrow::Cow;
use thiserror::Error;
use url::Url;

/// HTTP response container returned by `send`.
pub struct Response {
    /// Status code returned by the server.
    pub status: StatusCode,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

macro_rules! status_codes {
    ($(
        $variant:ident => ($code:literal, $reason:literal, $const_name:ident)
    ),+ $(,)?) => {
        /// HTTP status codes defined by RFC 9110 and related specifications.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
        #[repr(u16)]
        pub enum StatusCode {
            $(
                #[doc = $reason]
                $variant = $code,
            )+
        }

        impl StatusCode {
            /// Returns the numeric status code.
            pub const fn as_u16(self) -> u16 {
                self as u16
            }

            /// Returns the canonical reason phrase for this status code.
            pub const fn canonical_reason(self) -> &'static str {
                match self {
                    $(StatusCode::$variant => $reason,)+
                }
            }

            /// Converts a numeric status code into a `StatusCode` if known.
            pub const fn from_u16(code: u16) -> Option<Self> {
                match code {
                    $($code => Some(StatusCode::$variant),)+
                    _ => None,
                }
            }

            $(
                /// Alias matching reqwest's naming style.
                pub const $const_name: StatusCode = StatusCode::$variant;
            )+
        }

        impl std::fmt::Display for StatusCode {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} {}", self.as_u16(), self.canonical_reason())
            }
        }
    };
}

status_codes! {
    Continue => (100, "Continue", CONTINUE),
    SwitchingProtocols => (101, "Switching Protocols", SWITCHING_PROTOCOLS),
    Processing => (102, "Processing", PROCESSING),
    EarlyHints => (103, "Early Hints", EARLY_HINTS),
    Ok => (200, "OK", OK),
    Created => (201, "Created", CREATED),
    Accepted => (202, "Accepted", ACCEPTED),
    NonAuthoritativeInformation => (203, "Non-Authoritative Information", NON_AUTHORITATIVE_INFORMATION),
    NoContent => (204, "No Content", NO_CONTENT),
    ResetContent => (205, "Reset Content", RESET_CONTENT),
    PartialContent => (206, "Partial Content", PARTIAL_CONTENT),
    MultiStatus => (207, "Multi-Status", MULTI_STATUS),
    AlreadyReported => (208, "Already Reported", ALREADY_REPORTED),
    ImUsed => (226, "IM Used", IM_USED),
    MultipleChoices => (300, "Multiple Choices", MULTIPLE_CHOICES),
    MovedPermanently => (301, "Moved Permanently", MOVED_PERMANENTLY),
    Found => (302, "Found", FOUND),
    SeeOther => (303, "See Other", SEE_OTHER),
    NotModified => (304, "Not Modified", NOT_MODIFIED),
    UseProxy => (305, "Use Proxy", USE_PROXY),
    TemporaryRedirect => (307, "Temporary Redirect", TEMPORARY_REDIRECT),
    PermanentRedirect => (308, "Permanent Redirect", PERMANENT_REDIRECT),
    BadRequest => (400, "Bad Request", BAD_REQUEST),
    Unauthorized => (401, "Unauthorized", UNAUTHORIZED),
    PaymentRequired => (402, "Payment Required", PAYMENT_REQUIRED),
    Forbidden => (403, "Forbidden", FORBIDDEN),
    NotFound => (404, "Not Found", NOT_FOUND),
    MethodNotAllowed => (405, "Method Not Allowed", METHOD_NOT_ALLOWED),
    NotAcceptable => (406, "Not Acceptable", NOT_ACCEPTABLE),
    ProxyAuthenticationRequired => (407, "Proxy Authentication Required", PROXY_AUTHENTICATION_REQUIRED),
    RequestTimeout => (408, "Request Timeout", REQUEST_TIMEOUT),
    Conflict => (409, "Conflict", CONFLICT),
    Gone => (410, "Gone", GONE),
    LengthRequired => (411, "Length Required", LENGTH_REQUIRED),
    PreconditionFailed => (412, "Precondition Failed", PRECONDITION_FAILED),
    PayloadTooLarge => (413, "Content Too Large", PAYLOAD_TOO_LARGE),
    UriTooLong => (414, "URI Too Long", URI_TOO_LONG),
    UnsupportedMediaType => (415, "Unsupported Media Type", UNSUPPORTED_MEDIA_TYPE),
    RangeNotSatisfiable => (416, "Range Not Satisfiable", RANGE_NOT_SATISFIABLE),
    ExpectationFailed => (417, "Expectation Failed", EXPECTATION_FAILED),
    ImATeapot => (418, "I'm a teapot", IM_A_TEAPOT),
    MisdirectedRequest => (421, "Misdirected Request", MISDIRECTED_REQUEST),
    UnprocessableEntity => (422, "Unprocessable Content", UNPROCESSABLE_ENTITY),
    Locked => (423, "Locked", LOCKED),
    FailedDependency => (424, "Failed Dependency", FAILED_DEPENDENCY),
    TooEarly => (425, "Too Early", TOO_EARLY),
    UpgradeRequired => (426, "Upgrade Required", UPGRADE_REQUIRED),
    PreconditionRequired => (428, "Precondition Required", PRECONDITION_REQUIRED),
    TooManyRequests => (429, "Too Many Requests", TOO_MANY_REQUESTS),
    RequestHeaderFieldsTooLarge => (431, "Request Header Fields Too Large", REQUEST_HEADER_FIELDS_TOO_LARGE),
    UnavailableForLegalReasons => (451, "Unavailable For Legal Reasons", UNAVAILABLE_FOR_LEGAL_REASONS),
    InternalServerError => (500, "Internal Server Error", INTERNAL_SERVER_ERROR),
    NotImplemented => (501, "Not Implemented", NOT_IMPLEMENTED),
    BadGateway => (502, "Bad Gateway", BAD_GATEWAY),
    ServiceUnavailable => (503, "Service Unavailable", SERVICE_UNAVAILABLE),
    GatewayTimeout => (504, "Gateway Timeout", GATEWAY_TIMEOUT),
    HttpVersionNotSupported => (505, "HTTP Version Not Supported", HTTP_VERSION_NOT_SUPPORTED),
    VariantAlsoNegotiates => (506, "Variant Also Negotiates", VARIANT_ALSO_NEGOTIATES),
    InsufficientStorage => (507, "Insufficient Storage", INSUFFICIENT_STORAGE),
    LoopDetected => (508, "Loop Detected", LOOP_DETECTED),
    NotExtended => (510, "Not Extended", NOT_EXTENDED),
    NetworkAuthenticationRequired => (511, "Network Authentication Required", NETWORK_AUTHENTICATION_REQUIRED),
}

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
}

/// Common HTTP headers supported by the client, plus `Custom` for non-standard names.
#[derive(Clone)]
pub enum Header<'a> {
    /// Authorization header, e.g. "Bearer &lt;token&gt;".
    Authorization(Cow<'a, str>),
    /// Accept header describing accepted response types.
    Accept(Cow<'a, str>),
    /// Content-Type header describing request body type.
    ContentType(Cow<'a, str>),
    /// User-Agent header string.
    UserAgent(Cow<'a, str>),
    /// Accept-Encoding header for compression preferences.
    ///
    /// Common values include `gzip`, `br`, or `deflate`.
    AcceptEncoding(Cow<'a, str>),
    /// Accept-Language header for locale preferences.
    AcceptLanguage(Cow<'a, str>),
    /// Cache-Control header directives.
    CacheControl(Cow<'a, str>),
    /// Referer header.
    Referer(Cow<'a, str>),
    /// Origin header.
    Origin(Cow<'a, str>),
    /// Host header.
    Host(Cow<'a, str>),
    /// Custom header for non-standard names like "X-Request-Id".
    ///
    /// Header names must be valid RFC 9110 `token` values (tchar only).
    Custom(Cow<'a, str>, Cow<'a, str>),
}

/// Query parameter represented as a key-value pair.
#[derive(Clone)]
pub struct QueryParam<'a> {
    key: Cow<'a, str>,
    value: Cow<'a, str>,
}

/// Supported HTTP methods.
pub enum Method {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
    /// HTTP HEAD.
    Head,
    /// HTTP OPTIONS.
    Options,
    /// HTTP PATCH.
    Patch,
    /// HTTP CONNECT.
    Connect,
    /// HTTP TRACE.
    Trace,
}

struct Collector(Vec<u8>);

impl Handler for Collector {
    fn write(&mut self, data: &[u8]) -> Result<usize, WriteError> {
        self.0.extend_from_slice(data);
        Ok(data.len())
    }
}

/// Builder for constructing and sending a blocking HTTP request.
///
/// Defaults to GET when created via `Default`.
<<<<<<< Updated upstream
pub struct Curl<'a> {
    method: Method,
=======
pub struct Client<'a> {
    verb: Verb,
>>>>>>> Stashed changes
    headers: Vec<Header<'a>>,
    query: Vec<QueryParam<'a>>,
    body: Option<Body<'a>>,
    default_user_agent: Option<Cow<'a, str>>,
}

impl<'a> Default for Client<'a> {
    fn default() -> Self {
        Self {
            method: Method::Get,
            headers: Vec::new(),
            query: Vec::new(),
            body: None,
            default_user_agent: None,
        }
    }
}

impl<'a> Client<'a> {
    /// Creates a new builder with default settings (GET, no headers, no query).
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a new builder with a default User-Agent header.
    ///
    /// The User-Agent is only applied if the request does not already set one.
    pub fn with_user_agent(agent: impl Into<Cow<'a, str>>) -> Self {
        Self {
            default_user_agent: Some(agent.into()),
            ..Self::default()
        }
    }

    /// Sets the HTTP method explicitly.
    pub fn method(mut self, method: Method) -> Self {
        self.method = method;
        self
    }

    /// Sets the request method to GET.
    pub fn get(self) -> Self {
        self.method(Method::Get)
    }

    /// Sets the request method to POST.
    pub fn post(self) -> Self {
        self.method(Method::Post)
    }

    /// Sets the request method to PUT.
    pub fn put(self) -> Self {
        self.method(Method::Put)
    }

    /// Sets the request method to DELETE.
    pub fn delete(self) -> Self {
        self.method(Method::Delete)
    }

    /// Sets the request method to HEAD.
    pub fn head(self) -> Self {
        self.method(Method::Head)
    }

    /// Sets the request method to OPTIONS.
    pub fn options(self) -> Self {
        self.method(Method::Options)
    }

    /// Sets the request method to PATCH.
    pub fn patch(self) -> Self {
        self.method(Method::Patch)
    }

    /// Sets the request method to CONNECT.
    pub fn connect(self) -> Self {
        self.method(Method::Connect)
    }

    /// Sets the request method to TRACE.
    pub fn trace(self) -> Self {
        self.method(Method::Trace)
    }

    /// Adds a single header.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .header(curl_rest::Header::Authorization("Bearer token".into()))
    ///     .send("https://example.com/private")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Header validation happens in `send`.
    pub fn header(mut self, header: Header<'a>) -> Self {
        self.headers.push(header);
        self
    }

    /// Adds multiple headers.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .headers([
    ///         curl_rest::Header::Accept("application/json".into()),
    ///         curl_rest::Header::UserAgent("curl-rest/0.1".into()),
    ///     ])
    ///     .send("https://example.com/users")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Header validation happens in `send`.
    pub fn headers<I>(mut self, headers: I) -> Self
    where
        I: IntoIterator<Item = Header<'a>>,
    {
        self.headers.extend(headers);
        self
    }

    /// Adds a single query parameter.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .query_param(curl_rest::QueryParam::new("q", "rust"))
    ///     .send("https://example.com/search")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. URL validation happens in `send`.
    pub fn query_param(mut self, param: QueryParam<'a>) -> Self {
        self.query.push(param);
        self
    }

    /// Adds a single query parameter by key/value.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .query_param_kv("page", "1")
    ///     .send("https://example.com/search")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. URL validation happens in `send`.
    pub fn query_param_kv(
        self,
        key: impl Into<Cow<'a, str>>,
        value: impl Into<Cow<'a, str>>,
    ) -> Self {
        self.query_param(QueryParam::new(key, value))
    }

    /// Adds multiple query parameters.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .query_params([
    ///         curl_rest::QueryParam::new("sort", "desc"),
    ///         curl_rest::QueryParam::new("limit", "50"),
    ///     ])
    ///     .send("https://example.com/items")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. URL validation happens in `send`.
    pub fn query_params<I>(mut self, params: I) -> Self
    where
        I: IntoIterator<Item = QueryParam<'a>>,
    {
        self.query.extend(params);
        self
    }

    /// Sets a request body explicitly.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .post()
    ///     .body(curl_rest::Body::Text("hello".into()))
    ///     .send("https://example.com/echo")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Failures are reported by `send`.
    pub fn body(mut self, body: Body<'a>) -> Self {
        self.body = Some(body);
        self
    }

    /// Sets a raw byte body.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .post()
    ///     .body_bytes(vec![1, 2, 3])
    ///     .send("https://example.com/bytes")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Failures are reported by `send`.
    pub fn body_bytes(self, bytes: impl Into<Cow<'a, [u8]>>) -> Self {
        self.body(Body::Bytes(bytes.into()))
    }

    /// Sets a text body with a `text/plain; charset=utf-8` default content type.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .post()
    ///     .body_text("hello")
    ///     .send("https://example.com/echo")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Failures are reported by `send`.
    pub fn body_text(self, text: impl Into<Cow<'a, str>>) -> Self {
        self.body(Body::Text(text.into()))
    }

    /// Sets a JSON body with an `application/json` default content type.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .post()
    ///     .body_json(r#"{"name":"stanley"}"#)
    ///     .send("https://example.com/users")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    ///
    /// # Errors
    /// This method does not return errors. Failures are reported by `send`.
    pub fn body_json(self, json: impl Into<Cow<'a, str>>) -> Self {
        self.body(Body::Json(json.into()))
    }

    /// Sends the request to the provided URL.
    ///
    /// # Errors
    /// Returns an error if the URL is invalid, a header name or value is malformed, the
    /// status code is unrecognized, or libcurl reports a failure.
    pub fn send(self, url: &str) -> Result<Response, Error> {
        let mut easy = Easy2::new(Collector(Vec::new()));
        self.method.apply(&mut easy)?;
        let mut list = List::new();
        let mut has_headers = false;
        for header in &self.headers {
            list.append(&header.to_line()?)?;
            has_headers = true;
        }
        if let Some(default_user_agent) = &self.default_user_agent {
            if !self.has_user_agent_header() {
                list.append(&format!("User-Agent: {default_user_agent}"))?;
                has_headers = true;
            }
        }
        if let Some(content_type) = self.body_content_type() {
            if !self.has_content_type_header() {
                list.append(&format!("Content-Type: {content_type}"))?;
                has_headers = true;
            }
        }
        if has_headers {
            easy.http_headers(list)?;
        }
        if let Some(body) = &self.body {
            easy.post_fields_copy(body.bytes())?;
        }
        let url = add_query_params(url, &self.query);
        validate_url(url.as_ref())?;
        easy.url(url.as_ref())?;
        easy.perform()?;

        let status_code = easy.response_code()?;
        let status_u16 =
            u16::try_from(status_code).map_err(|_| Error::InvalidStatusCode(status_code))?;
        let status =
            StatusCode::from_u16(status_u16).ok_or(Error::InvalidStatusCode(status_code))?;
        let body = easy.get_ref().0.clone();
        Ok(Response { status, body })
    }

    fn has_content_type_header(&self) -> bool {
        self.headers.iter().any(|header| match header {
            Header::ContentType(_) => true,
            Header::Custom(name, _) => name.eq_ignore_ascii_case("Content-Type"),
            _ => false,
        })
    }

    fn has_user_agent_header(&self) -> bool {
        self.headers.iter().any(|header| match header {
            Header::UserAgent(_) => true,
            Header::Custom(name, _) => name.eq_ignore_ascii_case("User-Agent"),
            _ => false,
        })
    }

    fn body_content_type(&self) -> Option<&'static str> {
        match &self.body {
            Some(Body::Json(_)) => Some("application/json"),
            Some(Body::Text(_)) => Some("text/plain; charset=utf-8"),
            Some(Body::Bytes(_)) => None,
            None => None,
        }
    }
}

impl Method {
    fn apply(&self, easy: &mut Easy2<Collector>) -> Result<(), Error> {
        match self {
            Method::Get => easy.get(true)?,
            Method::Post => easy.post(true)?,
            Method::Put => easy.custom_request("PUT")?,
            Method::Delete => easy.custom_request("DELETE")?,
            Method::Head => easy.nobody(true)?,
            Method::Options => easy.custom_request("OPTIONS")?,
            Method::Patch => easy.custom_request("PATCH")?,
            Method::Connect => easy.custom_request("CONNECT")?,
            Method::Trace => easy.custom_request("TRACE")?,
        }
        Ok(())
    }
}

impl Header<'_> {
    fn to_line(&self) -> Result<String, Error> {
        let name = self.name();
        let value = self.value();
        if value.contains('\n') || value.contains('\r') {
            return Err(Error::InvalidHeaderValue(name.to_string()));
        }
        if matches!(self, Header::Custom(_, _)) {
            validate_header_name(name)?;
        }
        match self {
            Header::Authorization(value) => Ok(format!("Authorization: {value}")),
            Header::Accept(value) => Ok(format!("Accept: {value}")),
            Header::ContentType(value) => Ok(format!("Content-Type: {value}")),
            Header::UserAgent(value) => Ok(format!("User-Agent: {value}")),
            Header::AcceptEncoding(value) => Ok(format!("Accept-Encoding: {value}")),
            Header::AcceptLanguage(value) => Ok(format!("Accept-Language: {value}")),
            Header::CacheControl(value) => Ok(format!("Cache-Control: {value}")),
            Header::Referer(value) => Ok(format!("Referer: {value}")),
            Header::Origin(value) => Ok(format!("Origin: {value}")),
            Header::Host(value) => Ok(format!("Host: {value}")),
            Header::Custom(name, value) => Ok(format!("{}: {}", name, value)),
        }
    }

    fn name(&self) -> &str {
        match self {
            Header::Authorization(_) => "Authorization",
            Header::Accept(_) => "Accept",
            Header::ContentType(_) => "Content-Type",
            Header::UserAgent(_) => "User-Agent",
            Header::AcceptEncoding(_) => "Accept-Encoding",
            Header::AcceptLanguage(_) => "Accept-Language",
            Header::CacheControl(_) => "Cache-Control",
            Header::Referer(_) => "Referer",
            Header::Origin(_) => "Origin",
            Header::Host(_) => "Host",
            Header::Custom(name, _) => name.as_ref(),
        }
    }

    fn value(&self) -> &str {
        match self {
            Header::Authorization(value) => value.as_ref(),
            Header::Accept(value) => value.as_ref(),
            Header::ContentType(value) => value.as_ref(),
            Header::UserAgent(value) => value.as_ref(),
            Header::AcceptEncoding(value) => value.as_ref(),
            Header::AcceptLanguage(value) => value.as_ref(),
            Header::CacheControl(value) => value.as_ref(),
            Header::Referer(value) => value.as_ref(),
            Header::Origin(value) => value.as_ref(),
            Header::Host(value) => value.as_ref(),
            Header::Custom(_, value) => value.as_ref(),
        }
    }
}

pub enum Body<'a> {
    /// JSON text body.
    Json(Cow<'a, str>),
    /// UTF-8 text body.
    Text(Cow<'a, str>),
    /// Raw bytes body.
    Bytes(Cow<'a, [u8]>),
}

impl Body<'_> {
    fn bytes(&self) -> &[u8] {
        match self {
            Body::Json(value) => value.as_bytes(),
            Body::Text(value) => value.as_bytes(),
            Body::Bytes(value) => value.as_ref(),
        }
    }
}

impl<'a> QueryParam<'a> {
    /// Creates a new query parameter.
    ///
    /// # Examples
    /// ```no_run
    /// let resp = curl_rest::Client::default()
    ///     .get()
    ///     .query_param(curl_rest::QueryParam::new("page", "2"))
    ///     .send("https://example.com/search")?;
    /// # Ok::<(), curl_rest::Error>(())
    /// ```
    pub fn new(key: impl Into<Cow<'a, str>>, value: impl Into<Cow<'a, str>>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

fn add_query_params<'a>(url: &'a str, params: &[QueryParam<'_>]) -> Cow<'a, str> {
    if params.is_empty() {
        return Cow::Borrowed(url);
    }

    let (base, fragment) = match url.split_once('#') {
        Some((base, fragment)) => (base, Some(fragment)),
        None => (url, None),
    };

    let mut out = String::with_capacity(base.len() + 1);
    out.push_str(base);

    if base.contains('?') {
        if !base.ends_with('?') && !base.ends_with('&') {
            out.push('&');
        }
    } else {
        out.push('?');
    }

    for (idx, param) in params.iter().enumerate() {
        if idx > 0 {
            out.push('&');
        }
        out.push_str(&encode_query_component(param.key.as_ref()));
        out.push('=');
        out.push_str(&encode_query_component(param.value.as_ref()));
    }

    if let Some(fragment) = fragment {
        out.push('#');
        out.push_str(fragment);
    }

    Cow::Owned(out)
}

fn encode_query_component(value: &str) -> String {
    utf8_percent_encode(value, NON_ALPHANUMERIC).to_string()
}

fn validate_url(url: &str) -> Result<(), Error> {
    Url::parse(url)
        .map(|_| ())
        .map_err(|_| Error::InvalidUrl(url.to_string()))
}

fn validate_header_name(name: &str) -> Result<(), Error> {
    if name.is_empty() {
        return Err(Error::InvalidHeaderName(name.to_string()));
    }
    for b in name.bytes() {
        if !is_tchar(b) {
            return Err(Error::InvalidHeaderName(name.to_string()));
        }
    }
    Ok(())
}

fn is_tchar(b: u8) -> bool {
    matches!(
        b,
        b'!' | b'#' | b'$' | b'%' | b'&' | b'\'' | b'*' | b'+' | b'-' | b'.' | b'^' | b'_' | b'`'
            | b'|' | b'~' | b'0'..=b'9' | b'a'..=b'z' | b'A'..=b'Z'
    )
}

/// Sends a request with the given method and URL using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, the status code is unrecognized, or
/// libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::request(curl_rest::Method::Get, "https://example.com")?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
<<<<<<< Updated upstream
pub fn request(method: Method, url: &str) -> Result<Response, Error> {
    Curl::default().method(method).send(url)
=======
pub fn request(verb: Verb, url: &str) -> Result<Response, Error> {
    Client::default().verb(verb).send(url)
>>>>>>> Stashed changes
}

/// Sends a request with the given method, URL, and headers using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, a header name or value is malformed, the
/// status code is unrecognized, or libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::request_with_headers(
///     curl_rest::Method::Get,
///     "https://example.com",
///     &[curl_rest::Header::AcceptEncoding("gzip".into())],
/// )?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
pub fn request_with_headers(
    method: Method,
    url: &str,
    headers: &[Header<'_>],
) -> Result<Response, Error> {
<<<<<<< Updated upstream
    Curl::default()
        .method(method)
=======
    Client::default()
        .verb(verb)
>>>>>>> Stashed changes
        .headers(headers.iter().cloned())
        .send(url)
}

/// Sends a GET request using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, the status code is unrecognized, or
/// libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::get("https://example.com")?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
pub fn get(url: &str) -> Result<Response, Error> {
    Client::default().get().send(url)
}

/// Sends a POST request using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, the status code is unrecognized, or
/// libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::post("https://example.com")?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
pub fn post(url: &str) -> Result<Response, Error> {
    Client::default().post().send(url)
}

/// Sends a GET request with headers using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, a header name or value is malformed, the
/// status code is unrecognized, or libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::get_with_headers(
///     "https://example.com",
///     &[curl_rest::Header::AcceptEncoding("gzip".into())],
/// )?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
pub fn get_with_headers(url: &str, headers: &[Header<'_>]) -> Result<Response, Error> {
    Client::default()
        .get()
        .headers(headers.iter().cloned())
        .send(url)
}

/// Sends a POST request with headers using default builder settings.
///
/// # Errors
/// Returns an error if the URL is invalid, a header name or value is malformed, the
/// status code is unrecognized, or libcurl reports a failure.
///
/// # Examples
/// ```no_run
/// let resp = curl_rest::post_with_headers(
///     "https://example.com",
///     &[curl_rest::Header::AcceptEncoding("gzip".into())],
/// )?;
/// println!("Status: {}", resp.status);
/// # Ok::<(), curl_rest::Error>(())
/// ```
pub fn post_with_headers(url: &str, headers: &[Header<'_>]) -> Result<Response, Error> {
    Client::default()
        .post()
        .headers(headers.iter().cloned())
        .send(url)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_params_are_encoded_and_appended() {
        let params = [
            QueryParam::new("q", "rust curl"),
            QueryParam::new("page", "1"),
        ];
        let url = add_query_params("https://example.com/search", &params);
        assert_eq!(
            url.as_ref(),
            "https://example.com/search?q=rust%20curl&page=1"
        );
    }

    #[test]
    fn query_params_preserve_fragments() {
        let params = [QueryParam::new("a", "b")];
        let url = add_query_params("https://example.com/path#frag", &params);
        assert_eq!(url.as_ref(), "https://example.com/path?a=b#frag");
    }

    #[test]
    fn query_params_noop_is_borrowed() {
        let url = add_query_params("https://example.com", &[]);
        assert!(matches!(url, Cow::Borrowed(_)));
    }

    #[test]
    fn header_rejects_newlines() {
        let header = Header::UserAgent("bad\r\nvalue".into());
        let err = header.to_line().expect_err("expected invalid header");
        assert!(matches!(err, Error::InvalidHeaderValue(name) if name == "User-Agent"));
    }

    #[test]
    fn custom_header_rejects_invalid_name() {
        let header = Header::Custom("X Bad".into(), "ok".into());
        let err = header.to_line().expect_err("expected invalid header name");
        assert!(matches!(err, Error::InvalidHeaderName(name) if name == "X Bad"));
    }

    #[test]
    fn custom_header_allows_standard_token_chars() {
        let header = Header::Custom("X-Request-Id".into(), "abc123".into());
        let line = header.to_line().expect("expected valid header");
        assert_eq!(line, "X-Request-Id: abc123");
    }

    #[test]
    fn body_content_type_defaults() {
        let curl = Client::default().body_json(r#"{"ok":true}"#);
        assert_eq!(curl.body_content_type(), Some("application/json"));

        let curl = Client::default().body_text("hi");
        assert_eq!(curl.body_content_type(), Some("text/plain; charset=utf-8"));
    }

    #[test]
    fn content_type_header_overrides_body_default() {
        let curl = Client::default()
            .body_json(r#"{"ok":true}"#)
            .header(Header::ContentType("application/custom+json".into()));
        assert!(curl.has_content_type_header());
        assert_eq!(curl.body_content_type(), Some("application/json"));
    }

    #[test]
    fn with_user_agent_sets_default() {
        let curl = Client::with_user_agent("my-agent/1.0");
        assert_eq!(curl.default_user_agent.as_deref(), Some("my-agent/1.0"));
    }

    #[test]
    fn user_agent_detection_handles_custom_header() {
        let curl = Client::default().header(Header::Custom("User-Agent".into(), "custom".into()));
        assert!(curl.has_user_agent_header());
    }

    #[test]
    fn url_validation_rejects_invalid_urls() {
        let err = validate_url("http://[::1").expect_err("expected invalid url");
        assert!(matches!(err, Error::InvalidUrl(_)));
    }

    #[test]
    fn query_params_append_to_existing_query() {
        let params = [QueryParam::new("b", "2")];
        let url = add_query_params("https://example.com/path?a=1", &params);
        assert_eq!(url.as_ref(), "https://example.com/path?a=1&b=2");
    }

    #[test]
    fn query_params_encode_unicode() {
        let params = [QueryParam::new("q", "café")];
        let url = add_query_params("https://example.com/search", &params);
        assert_eq!(url.as_ref(), "https://example.com/search?q=caf%C3%A9");
    }

    #[test]
    fn header_name_and_value_match() {
        let header = Header::Accept("application/json".into());
        assert_eq!(header.name(), "Accept");
        assert_eq!(header.value(), "application/json");
    }
}
