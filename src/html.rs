// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! Login and error page, built from the templates in deploy/html/ (embedded at build time).

const STYLE: &str = include_str!("../deploy/html/style.css");
const LOGIN: &str = include_str!("../deploy/html/login.html");
const ERROR: &str = include_str!("../deploy/html/error.html");

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

/// Replace `{{name}}` placeholders in one pass. Values are inserted as they are
/// (escape them first) and are not scanned again. Unknown placeholders stay.
fn render(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len() + 1024);
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            rest = &rest[start..];
            break;
        };
        let key = after[..end].trim();
        match vars.iter().find(|(k, _)| *k == key) {
            Some((_, v)) => out.push_str(v),
            None => out.push_str(&rest[start..start + end + 4]),
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
}

pub fn login_page(
    title: &str,
    hidden: &[(&str, &str)],
    username: &str,
    error: Option<&str>,
) -> String {
    let error = error
        .map(|e| format!("<p class=\"err\" role=\"alert\">{}</p>", escape(e)))
        .unwrap_or_default();
    let hidden: String = hidden
        .iter()
        .map(|(k, v)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                escape(k),
                escape(v)
            )
        })
        .collect();
    let (focus_user, focus_password) = if username.is_empty() {
        (" autofocus", "")
    } else {
        ("", " autofocus")
    };
    render(
        LOGIN,
        &[
            ("title", &escape(title)),
            ("style", STYLE),
            ("error", &error),
            ("hidden", &hidden),
            ("username", &escape(username)),
            ("focus_user", focus_user),
            ("focus_password", focus_password),
        ],
    )
}

pub fn error_page(title: &str, message: &str) -> String {
    render(
        ERROR,
        &[
            ("title", &escape(title)),
            ("style", STYLE),
            ("message", &escape(message)),
        ],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_not_rendered_again() {
        let out = render("a {{x}} b {{y}}", &[("x", "{{y}}"), ("y", "Y")]);
        assert_eq!(out, "a {{y}} b Y");
    }

    #[test]
    fn unknown_and_unclosed_placeholders_stay() {
        assert_eq!(render("{{nope}} {{open", &[]), "{{nope}} {{open");
    }

    #[test]
    fn login_page_escapes_input() {
        let page = login_page("T", &[("state", "\"><script>")], "<b>", Some("<x>"));
        assert!(!page.contains("<script>") && !page.contains("<b>") && !page.contains("<x>"));
        assert!(!page.contains("{{"), "all placeholders filled");
    }
}
