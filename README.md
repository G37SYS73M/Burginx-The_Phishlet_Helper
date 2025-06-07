# Burginx – Burp Phishlet Generator __version__ = "1.0.0"

A Burp Suite extension (Jython/Python 2.7) for quickly extracting login credentials, session cookies, and generating Evilginx-compatible Phishlet YAML.

## Features

- **Record** HTTP history or right-click → “Send to Phishlet Gen” to queue requests.
- **Inspect** raw request/response pairs inline.
- **Highlight & Extract** arbitrary POST fields and Set-Cookie values.
- **Generate** a fully-formed Evilginx v2 Phishlet YAML (author, proxy_hosts, auth_tokens, credentials, login endpoint).
- **Edit & Save** the generated YAML from within Burp.

## Installation

1. Download or clone this repo.
2. In Burp → **Extender** → **Options**:
   - Set the Python environment to your Jython standalone JAR (e.g. `jython-standalone-2.7.2.jar`).
3. In Burp → **Extender** → **Extensions** → **Add**:
   - Type: Python
   - Extension file: `burp_extender.py`
4. Switch to the **Phishlet Gen** tab.

## Usage

1. **Capture** requests in Proxy/Repeater/etc.  
2. **Right-click** any request → **Send to Phishlet Gen**.  
3. **Extract**:
   - Select your queued request in the list.
   - Switch between “Creds” or “Cookies” mode.
   - Highlight text in the raw viewer, then click **Get from Selection** (you can repeat to accumulate multiple fields).  
4. **Generate/Edit YAML**:
   - Flip to the second tab, click **Generate YAML** to auto-populate.
   - Make any edits, then click **Save YAML**.

## Phishlet Format

Generated YAML follows the [Evilginx v2 phishlet schema](https://help.evilginx.com/community/phishlet-format).

## Development & Contributing

- PRs welcome!  
- Please run Burp in a temporary project, load the extension, and verify your changes locally.

---