use std::borrow::Cow;

use crate::StatusCode;

/// HTTP response container returned by `send`.
#[derive(Debug, Clone, Default)]
pub struct Response {
    /// Status code returned by the server.
    pub status: StatusCode,
    /// Response headers in received order (including duplicates).
    pub headers: Vec<ResponseHeader>,
    /// Raw response body bytes.
    pub body: Vec<u8>,
}

/// A single HTTP response header entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResponseHeader {
    /// Header name as received.
    pub name: String,
    /// Header value as received (trimmed).
    pub value: String,
}

/// Common HTTP headers supported by the client, plus `Custom` for nonstandard names.
#[derive(Debug, Clone, PartialEq)]
pub enum Header<'a> {
    /// Authorization header, e.g. "Bearer &Lt;token&gt;".
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
    /// Custom header for nonstandard names like "X-Request-Id".
    ///
    /// Header names must be valid RFC 9110 `token` values (tchar only).
    Custom(Cow<'a, str>, Cow<'a, str>),
}

/// Query parameter represented as a key-value pair.
#[derive(Clone)]
pub struct QueryParam<'a> {
    pub(crate) key: Cow<'a, str>,
    pub(crate) value: Cow<'a, str>,
}

/// Supported HTTP methods.
#[derive(Debug, Default, Clone)]
pub enum Method {
    /// HTTP GET.
    #[default]
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
