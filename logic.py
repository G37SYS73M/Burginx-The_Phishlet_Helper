import re
from phishlet_generator import Phishlet

_callbacks = None
_helpers = None
_history = []
_extracted = {}

def init(callbacks):
    global _callbacks, _helpers
    _callbacks = callbacks
    _helpers = callbacks.getHelpers()

def on_message(toolFlag, isRequest, messageInfo):
    # Store history entries
    _history.append((toolFlag, isRequest, messageInfo))

def extract(trigger_indices, error_regex):
    global _extracted
    _extracted = {'cookies': [], 'auth': None, 'post': None}
    # 1. Replay triggers to capture tokens
    for idx in trigger_indices:
        _, isReq, msg = _history[idx]
        if isReq:
            # send and get response
            resp = _callbacks.makeHttpRequest(msg.getHttpService(), msg.getRequest())
            body = _helpers.bytesToString(resp.getResponse())
            # extract cookie headers
            for hdr in resp.getResponseHeaders():
                if hdr.lower().startswith('set-cookie:'):
                    _extracted['cookies'].append(hdr.split(':',1)[1].strip())
            # extract auth token via regex
            m = re.search(r"Authorization: Bearer\s*(\S+)", '\n'.join(resp.getResponseHeaders()))
            if m:
                _extracted['auth'] = m.group(1)
            # extract POST data
            if msg.getRequest().startswith('POST'):
                post = _helpers.bytesToString(msg.getRequest()).split('\r\n\r\n',1)[1]
                _extracted['post'] = post
    # 2. Check error condition
    # (skipped: you may implement status-code or body-pattern matching)
    return _extracted

def generate_yaml(path):
    phish = Phishlet(
        domain="example.com",
        cookies=_extracted['cookies'],
        authorization=_extracted['auth'],
        post_data=_extracted['post']
    )
    with open(path, 'w') as f:
        f.write(phish.to_yaml())

# File: phishlet_generator.py
from datetime import datetime

def indent(level):
    return '  ' * level

class Phishlet:
    def __init__(self, domain, cookies, authorization, post_data):
        self.domain = domain
        self.cookies = cookies or []
        self.authorization = authorization
        self.post_data = post_data
        self.generated_at = datetime.utcnow()

    def to_yaml(self):
        lines = []
        lines.append(f"# Phishlet generated at {self.generated_at.isoformat()}Z")
        lines.append(f"phishlet:")
        lines.append(f"  name: {self.domain}")
        lines.append(f"  upstream: https://{self.domain}")
        lines.append(f"  listen: :443")
        lines.append("  locations:")
        lines.append("    login:")
        lines.append(indent(3) + "path: /login")
        lines.append(indent(3) + "endpoint: true")
        lines.append(indent(3) + "upstream: https://{self.domain}/login")
        lines.append(indent(3) + "auth:")
        if self.authorization:
            lines.append(indent(4) + f"header: 'Authorization: Bearer {self.authorization}'")
        if self.cookies:
            lines.append(indent(4) + "set_cookie:")
            for c in self.cookies:
                lines.append(indent(5) + f"- '{c}'")
        lines.append(indent(3) + "body: |")
        for line in (self.post_data or '').splitlines():
            lines.append(indent(4) + line)
        return "\n".join(lines)