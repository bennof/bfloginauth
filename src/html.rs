// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! Embedded login page (no JavaScript).

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

const STYLE: &str = r#"
:root{--bg:#f4f5f7;--card:#fff;--fg:#1d2330;--muted:#5d6577;--border:#d5d9e0;--accent:#2f5bd3;--accent-fg:#fff;--err-bg:#fdecec;--err-fg:#9b1c1c}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8ec;--muted:#9aa2b1;--border:#343a45;--accent:#6b8cff;--accent-fg:#0b0d12;--err-bg:#3a1f22;--err-fg:#ffb4b4}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:16px}
main{width:100%;max-width:360px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:32px 28px}
h1{margin:0 0 24px;font-size:22px;font-weight:600}
label{display:block;font-size:14px;color:var(--muted);margin:0 0 6px}
input{width:100%;padding:10px 12px;font:inherit;color:var(--fg);background:var(--bg);border:1px solid var(--border);border-radius:8px;margin:0 0 16px}
input:focus{outline:2px solid var(--accent);outline-offset:1px;border-color:transparent}
button{width:100%;padding:11px;font:inherit;font-weight:600;color:var(--accent-fg);background:var(--accent);border:0;border-radius:8px;cursor:pointer;margin-top:8px}
.err{background:var(--err-bg);color:var(--err-fg);padding:10px 12px;border-radius:8px;margin:0 0 16px;font-size:14px}
"#;

fn layout(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
<meta name=\"robots\" content=\"noindex\"><title>{t}</title><style>{STYLE}</style></head>\
<body><main>{body}</main></body></html>",
        t = escape(title)
    )
}

pub fn login_page(
    title: &str,
    hidden: &[(&str, &str)],
    username: &str,
    error: Option<&str>,
) -> String {
    let mut body = format!("<h1>{}</h1>", escape(title));
    if let Some(e) = error {
        body.push_str(&format!(
            "<p class=\"err\" role=\"alert\">{}</p>",
            escape(e)
        ));
    }
    // No action attribute: the form posts to the same URL, which also works under an nginx path prefix.
    body.push_str("<form method=\"post\">");
    for (k, v) in hidden {
        body.push_str(&format!(
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escape(k),
            escape(v)
        ));
    }
    let autofocus_user = if username.is_empty() {
        " autofocus"
    } else {
        ""
    };
    let autofocus_pw = if username.is_empty() {
        ""
    } else {
        " autofocus"
    };
    body.push_str(&format!(
        "<label for=\"u\">User name</label>\
<input id=\"u\" name=\"username\" autocomplete=\"username\" required value=\"{}\"{autofocus_user}>\
<label for=\"p\">Password</label>\
<input id=\"p\" name=\"password\" type=\"password\" autocomplete=\"current-password\" required{autofocus_pw}>\
<button type=\"submit\">Sign in</button></form>",
        escape(username)
    ));
    layout(title, &body)
}

pub fn error_page(title: &str, message: &str) -> String {
    layout(
        title,
        &format!(
            "<h1>{}</h1><p class=\"err\" role=\"alert\">{}</p>",
            escape(title),
            escape(message)
        ),
    )
}
