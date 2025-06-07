# Python Burp Extension: Phishlet Generator

This Burp extension in Python (Jython) extracts session cookies, authorization tokens, and POST data from Burp HTTP history using regex-based rules, and then generates a Phishlet YAML file suitable for Evilginx3/Evilginx2.

## Prerequisites
- Burp Suite Professional
- Jython standalone JAR (e.g., jython-standalone-2.7.2.jar)
- Add this extension under `Extender → Options → Python Environment` pointing to the Jython JAR.

## Installation
1. Download `phishlet_generator.py`, `ui.py`, `logic.py`, and `burp_extender.py` into a folder.
2. In Burp, go to `Extender → Extensions → Add`:
   - Type: Python
   - Extension file: `burp_extender.py`
   - Ensure Jython environment is configured.

## Usage
1. Open the new `Phishlet Gen` tab in Burp.
2. Configure a trigger sequence and error conditions.
3. Extract tokens via the extension UI.
4. Click `Generate YAML` to save a Phishlet file.

---