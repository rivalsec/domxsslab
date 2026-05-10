# xss_lab

Flask test site exposing every common DOM/reflected XSS sink, plus one blacklist-"protected" endpoint.

**For authorized testing and education only.** Do not deploy to a public host.

## Install & run

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Serves on `http://127.0.0.1:5000` with `debug=True`.

## Endpoints

- `/` — index page.
- `/sitemap` — auto-generated list of every route.
- `/sink/<name>` — one route per sink category. See [app.py](app.py) for the full list. Categories:
  - HTML: `innerhtml`, `innerhtml-hash`, `outerhtml`, `document-write`, `document-writeln`, `insertadjacenthtml`, `domparser`, `createcontextualfragment`
  - Attribute / property: `href`, `src`, `action`, `setattribute`, `style`
  - JS execution: `eval`, `eval-raw`, `function-constructor`, `settimeout`, `setinterval`, `script-src`, `script-text`
  - URL / navigation: `location`, `open`
  - Storage / messaging: `postmessage`, `websocket`
  - jQuery: `jquery-html`, `jquery-append`, `jquery-selector`
  - Reflected (server-rendered): `reflected-html`, `reflected-script`
- `/protected?input=...` — blacklist filter ([app.py:172-208](app.py#L172-L208)). Blocks ~30 regex patterns (`<script`, `on\w+=`, `javascript:`, common tags, `eval(`, `document.`, etc.). Useful for testing bypasses.

## Layout

- [app.py](app.py) — Flask routes.
- [templates/](templates/) — one HTML file per sink under `templates/sinks/`, plus `base.html`, `index.html`, `sitemap.html`, and the protected pages.
