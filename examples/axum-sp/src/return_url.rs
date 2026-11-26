use url::Url;

/// The URL a finished login returns to.
///
/// `requested` is resolved against `base` as a browser resolves a link,
/// backslashes included. A URL on another origin, or one that does not
/// parse, returns the root of `base`.
pub(crate) fn same_origin_return_url(base: &Url, requested: Option<&str>) -> Url {
    requested
        .and_then(|requested| base.join(requested).ok())
        .filter(|resolved| resolved.origin() == base.origin())
        .unwrap_or_else(|| {
            let mut root = base.clone();
            root.set_path("/");
            root.set_query(None);
            root.set_fragment(None);
            root
        })
}
