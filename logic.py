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
    # Automatically record requests from history
    if messageIsRequest:
        _history.append((toolFlag, True, messageInfo))

def store_from_context(toolFlag, messageInfo):
    # Add a single context-invoked request to history and return its index
    _history.append((toolFlag, True, messageInfo))
    return len(_history) - 1

def extract(trigger_indices, error_regex):
    global _extracted
    _extracted = {'cookies': [], 'auth': None, 'post': None}
    pattern = re.compile(error_regex)
    last_resp = None
    # 1. Replay triggers to capture tokens
    for idx in trigger_indices:
        try:
            toolFlag, isReq, msg = _history[idx]
        except IndexError:
            continue
        if isReq:
            httpService = msg.getHttpService()
            _callbacks.printOutput("Replaying request %d to %s" % (idx, httpService))
            resp = _callbacks.makeHttpRequest(httpService, msg.getRequest())
            last_resp = resp
            headers = resp.getResponseHeaders()
            # extract cookie headers and auth token
            for hdr in headers:
                low = hdr.lower()
                if low.startswith('set-cookie:'):
                    _extracted['cookies'].append(hdr.split(':',1)[1].strip())
                if 'authorization: bearer' in low:
                    parts = hdr.split(None, 2)
                    if len(parts) >= 3:
                        _extracted['auth'] = parts[2].strip()
            # extract POST data
            req_str = _helpers.bytesToString(msg.getRequest())
            if req_str.upper().startswith('POST'):
                parts = req_str.split('\r\n\r\n',1)
                if len(parts) == 2:
                    _extracted['post'] = parts[1]
    # Optionally validate error condition on last response
    if last_resp:
        body = _helpers.bytesToString(last_resp.getResponse())
        if not pattern.search(body):
            _callbacks.printOutput("Warning: error regex did not match last response")
    return _extracted

def generate_yaml(path):
    phish = Phishlet(
        domain="example.com",
        cookies=_extracted.get('cookies'),
        authorization=_extracted.get('auth'),
        post_data=_extracted.get('post')
    )
    f = open(path, 'w')
    f.write(phish.to_yaml())
    f.close()
