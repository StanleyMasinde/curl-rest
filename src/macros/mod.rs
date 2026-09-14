#[macro_export]
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

        impl Display for StatusCode {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{} {}", self.as_u16(), self.canonical_reason())
            }
        }

        impl Default for StatusCode {
            fn default() -> Self {
                StatusCode::Ok
            }
        }
    };
}
