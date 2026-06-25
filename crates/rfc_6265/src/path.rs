//! RFC 6265 §5.1.4 paths and path-match.
//!
//! <https://www.rfc-editor.org/rfc/rfc6265#section-5.1.4>

/// The **default-path** for a cookie given the request-URI's path component, per RFC 6265 §5.1.4:
/// the path up to (but not including) the right-most `/`, or `/` when the path is empty, is
/// relative (no leading `/`), or contains only the leading `/`.
#[must_use]
pub fn default_path(uri_path: &str) -> &str {
    if !uri_path.starts_with('/') {
        return "/";
    }
    match uri_path.rfind('/') {
        // Only the leading `/` (or, unreachably, none) → no usable prefix.
        Some(0) | None => "/",
        Some(idx) => &uri_path[..idx],
    }
}

/// Whether `request_path` **path-matches** `cookie_path` per RFC 6265 §5.1.4: they are identical,
/// or `cookie_path` is a prefix of `request_path` and either `cookie_path` ends with `/` or the
/// first character of `request_path` not covered by `cookie_path` is `/`.
#[must_use]
pub fn path_matches(request_path: &str, cookie_path: &str) -> bool {
    if request_path == cookie_path {
        return true;
    }
    let Some(rest) = request_path.strip_prefix(cookie_path) else {
        return false;
    };
    cookie_path.ends_with('/') || rest.starts_with('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_path_examples() {
        assert_eq!(default_path("/a/b/c"), "/a/b");
        assert_eq!(default_path("/a/"), "/a");
        assert_eq!(default_path("/foo"), "/");
        assert_eq!(default_path("/"), "/");
        assert_eq!(default_path(""), "/");
        assert_eq!(default_path("relative/path"), "/");
    }

    #[test]
    fn path_match_identical_and_boundary_prefix() {
        assert!(path_matches("/a/b", "/a/b")); // identical
        assert!(path_matches("/a/b", "/a")); // prefix, next char '/'
        assert!(path_matches("/a/b", "/a/")); // prefix, cookie-path ends '/'
        assert!(path_matches("/", "/"));
    }

    #[test]
    fn path_match_rejects_non_boundary_or_non_prefix() {
        assert!(!path_matches("/ab", "/a")); // prefix but next char is not '/'
        assert!(!path_matches("/a", "/a/b")); // cookie-path longer
        assert!(!path_matches("/x/y", "/a")); // not a prefix
    }
}
