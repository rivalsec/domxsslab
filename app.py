"""
DOM XSS Lab — Flask test site with every category of DOM XSS sink.
For authorized security testing / education only.
"""
import re

from flask import Flask, render_template, request

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


# ---------- HTML sinks ----------
@app.route("/sink/innerhtml")
def sink_innerhtml():
    return render_template("sinks/innerhtml.html")


@app.route("/sink/innerhtml-hash")
def sink_innerhtml_hash():
    return render_template("sinks/innerhtml_hash.html")


@app.route("/sink/outerhtml")
def sink_outerhtml():
    return render_template("sinks/outerhtml.html")


@app.route("/sink/document-write")
def sink_document_write():
    return render_template("sinks/document_write.html")


@app.route("/sink/document-writeln")
def sink_document_writeln():
    return render_template("sinks/document_writeln.html")


@app.route("/sink/insertadjacenthtml")
def sink_insertadjacenthtml():
    return render_template("sinks/insertadjacenthtml.html")


@app.route("/sink/domparser")
def sink_domparser():
    return render_template("sinks/domparser.html")


@app.route("/sink/createcontextualfragment")
def sink_createcontextualfragment():
    return render_template("sinks/createcontextualfragment.html")


# ---------- Attribute / property sinks ----------
@app.route("/sink/href")
def sink_href():
    return render_template("sinks/href.html")


@app.route("/sink/src")
def sink_src():
    return render_template("sinks/src.html")


@app.route("/sink/action")
def sink_action():
    return render_template("sinks/action.html")


@app.route("/sink/setattribute")
def sink_setattribute():
    return render_template("sinks/setattribute.html")


@app.route("/sink/style")
def sink_style():
    return render_template("sinks/style.html")


# ---------- JavaScript execution sinks ----------
@app.route("/sink/eval")
def sink_eval():
    return render_template("sinks/eval.html")


@app.route("/sink/eval-raw")
def sink_eval_raw():
    return render_template("sinks/eval_raw.html")


@app.route("/sink/function-constructor")
def sink_function_constructor():
    return render_template("sinks/function_constructor.html")


@app.route("/sink/settimeout")
def sink_settimeout():
    return render_template("sinks/settimeout.html")


@app.route("/sink/setinterval")
def sink_setinterval():
    return render_template("sinks/setinterval.html")


@app.route("/sink/script-src")
def sink_script_src():
    return render_template("sinks/script_src.html")


@app.route("/sink/script-text")
def sink_script_text():
    return render_template("sinks/script_text.html")


# ---------- URL / navigation sinks ----------
@app.route("/sink/location")
def sink_location():
    return render_template("sinks/location.html")


@app.route("/sink/open")
def sink_open():
    return render_template("sinks/open.html")


# ---------- Storage / message sinks ----------
@app.route("/sink/postmessage")
def sink_postmessage():
    return render_template("sinks/postmessage.html")


@app.route("/sink/websocket")
def sink_websocket():
    return render_template("sinks/websocket.html")


# ---------- jQuery sinks ----------
@app.route("/sink/jquery-html")
def sink_jquery_html():
    return render_template("sinks/jquery_html.html")


@app.route("/sink/jquery-append")
def sink_jquery_append():
    return render_template("sinks/jquery_append.html")


@app.route("/sink/jquery-selector")
def sink_jquery_selector():
    return render_template("sinks/jquery_selector.html")


# ---------- Reflected XSS ----------
@app.route("/sink/reflected-html")
def sink_reflected_html():
    name = request.args.get("name", "world")
    return render_template("sinks/reflected_html.html", name=name)


@app.route("/sink/reflected-script")
def sink_reflected_script():
    name = request.args.get("name", "world")
    return render_template("sinks/reflected_script.html", name=name)


# ---------- Protected page ----------
XSS_PATTERNS = [
    re.compile(r'<\s*script', re.I),
    re.compile(r'on\w+\s*=', re.I),
    re.compile(r'javascript\s*:', re.I),
    re.compile(r'<\s*img\b', re.I),
    re.compile(r'<\s*svg\b', re.I),
    re.compile(r'<\s*iframe\b', re.I),
    re.compile(r'<\s*object\b', re.I),
    re.compile(r'<\s*embed\b', re.I),
    re.compile(r'<\s*link\b', re.I),
    re.compile(r'<\s*style\b', re.I),
    re.compile(r'<\s*math\b', re.I),
    re.compile(r'<\s*video\b', re.I),
    re.compile(r'<\s*audio\b', re.I),
    re.compile(r'<\s*body\b', re.I),
    re.compile(r'<\s*details\b', re.I),
    re.compile(r'<\s*marquee\b', re.I),
    re.compile(r'eval\s*\(', re.I),
    re.compile(r'alert\s*\(', re.I),
    re.compile(r'prompt\s*\(', re.I),
    re.compile(r'confirm\s*\(', re.I),
    re.compile(r'document\s*\.', re.I),
    re.compile(r'window\s*[\.\[]', re.I),
    re.compile(r'\.cookie', re.I),
    re.compile(r'data\s*:', re.I),
    re.compile(r'vbscript\s*:', re.I),
    re.compile(r'expression\s*\(', re.I),
    re.compile(r'url\s*\(', re.I),
]


def is_xss(value):
    """Check input against XSS blacklist patterns."""
    for pat in XSS_PATTERNS:
        if pat.search(value):
            return True
    return False


@app.route("/protected")
def protected():
    raw = request.args.get('input', '')
    if raw and is_xss(raw):
        return render_template("protected_blocked.html", raw=raw)
    return render_template("protected.html")


@app.route("/sitemap")
def sitemap():
    links = []
    for rule in sorted(app.url_map.iter_rules(), key=lambda r: r.rule):
        if rule.endpoint == 'static':
            continue
        links.append(rule.rule)
    base_url = request.url_root.rstrip('/')
    return render_template("sitemap.html", links=links, base_url=base_url)


if __name__ == "__main__":
    app.run(debug=True, port=5000)
