// Copyright (c) 2026 Benjamin Benno Falkner
// SPDX-License-Identifier: MIT

//! CLI commands that edit the config file. Changes go through `toml_edit` so
//! comments and formatting are preserved. Before saving, the new file is fully
//! validated and then replaced atomically.

use std::io::{BufRead, IsTerminal};
use std::path::Path;

use anyhow::{Context, Result, bail};
use argon2::Argon2;
use argon2::password_hash::{PasswordHasher, SaltString};
use toml_edit::{Array, DocumentMut, Item, Table, value};

use crate::config::{Config, check_redirect_url, check_username};

pub const EXAMPLE_CONFIG: &str = include_str!("../examples/bfloginauth.toml");

fn load_doc(path: &Path) -> Result<DocumentMut> {
    let text = std::fs::read_to_string(path).with_context(|| {
        format!(
            "Config {} kann nicht gelesen werden (erst `init`?)",
            path.display()
        )
    })?;
    text.parse()
        .with_context(|| format!("Config {} ist kein gültiges TOML", path.display()))
}

fn save_doc(path: &Path, doc: &DocumentMut) -> Result<()> {
    let text = doc.to_string();
    Config::parse(&text).context("Änderung würde eine ungültige Config erzeugen")?;
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, &text)?;
    // Keep the old file's permissions (the hashes are sensitive) and, when run
    // as root, its owner, so the service user can still read it.
    if let Ok(meta) = std::fs::metadata(path) {
        std::fs::set_permissions(&tmp, meta.permissions())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = std::os::unix::fs::chown(&tmp, Some(meta.uid()), Some(meta.gid()));
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

pub fn init(path: &Path) -> Result<()> {
    if path.exists() {
        bail!("{} existiert bereits", path.display());
    }
    std::fs::write(path, EXAMPLE_CONFIG)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    println!(
        "{} angelegt. Jetzt `user add <name>` ausführen.",
        path.display()
    );
    Ok(())
}

// ---------------------------------------------------------------- Passwords

/// Prompt for the password twice without echo, or read one line from stdin when there is no terminal.
pub fn read_password(from_stdin: bool) -> Result<String> {
    let pw = if from_stdin || !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        line.trim_end_matches(['\r', '\n']).to_string()
    } else {
        let a = rpassword::prompt_password("Passwort: ")?;
        let b = rpassword::prompt_password("Passwort wiederholen: ")?;
        if a != b {
            bail!("Passwörter stimmen nicht überein");
        }
        a
    };
    if pw.chars().count() < 8 {
        bail!("Passwort muss mindestens 8 Zeichen haben");
    }
    Ok(pw)
}

pub fn hash_password(pw: &str) -> Result<String> {
    Ok(Argon2::default()
        .hash_password(pw.as_bytes(), &SaltString::generate(&mut rand::rngs::OsRng))
        .map_err(|e| anyhow::anyhow!("Hashing fehlgeschlagen: {e}"))?
        .to_string())
}

// ---------------------------------------------------------------- Users

fn users_table(doc: &mut DocumentMut) -> Result<&mut Table> {
    if !doc.contains_key("users") {
        let mut t = Table::new();
        t.set_implicit(true);
        doc.insert("users", Item::Table(t));
    }
    doc["users"]
        .as_table_mut()
        .context("`users` muss eine Tabelle sein")
}

fn user_table<'a>(doc: &'a mut DocumentMut, name: &str) -> Result<&'a mut Table> {
    users_table(doc)?
        .get_mut(name)
        .and_then(Item::as_table_mut)
        .with_context(|| format!("Nutzer '{name}' existiert nicht"))
}

fn string_array<'a>(items: impl IntoIterator<Item = &'a String>) -> Array {
    items.into_iter().map(String::as_str).collect()
}

fn clean_roles(roles: &[String]) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for r in roles.iter().flat_map(|r| r.split(',')).map(str::trim) {
        if !r.is_empty() && !out.iter().any(|o| o == r) {
            out.push(r.to_string());
        }
    }
    out
}

pub fn user_add(path: &Path, name: &str, roles: &[String], from_stdin: bool) -> Result<()> {
    check_username(name)?;
    let mut doc = load_doc(path)?;
    if users_table(&mut doc)?.contains_key(name) {
        bail!("Nutzer '{name}' existiert bereits (Passwort ändern: `user passwd {name}`)");
    }
    let hash = hash_password(&read_password(from_stdin)?)?;
    let mut t = Table::new();
    t.insert("password_hash", value(hash));
    t.insert("roles", value(string_array(&clean_roles(roles))));
    users_table(&mut doc)?.insert(name, Item::Table(t));
    save_doc(path, &doc)?;
    println!("Nutzer '{name}' angelegt.");
    Ok(())
}

pub fn user_remove(path: &Path, name: &str) -> Result<()> {
    let mut doc = load_doc(path)?;
    if users_table(&mut doc)?.remove(name).is_none() {
        bail!("Nutzer '{name}' existiert nicht");
    }
    save_doc(path, &doc)?;
    println!("Nutzer '{name}' gelöscht.");
    Ok(())
}

pub fn user_passwd(path: &Path, name: &str, from_stdin: bool) -> Result<()> {
    let mut doc = load_doc(path)?;
    user_table(&mut doc, name)?; // fail early if the user does not exist
    let hash = hash_password(&read_password(from_stdin)?)?;
    user_table(&mut doc, name)?.insert("password_hash", value(hash));
    save_doc(path, &doc)?;
    println!("Passwort für '{name}' geändert.");
    Ok(())
}

pub fn user_set_disabled(path: &Path, name: &str, disabled: bool) -> Result<()> {
    let mut doc = load_doc(path)?;
    let t = user_table(&mut doc, name)?;
    if disabled {
        t.insert("disabled", value(true));
    } else {
        t.remove("disabled");
    }
    save_doc(path, &doc)?;
    println!(
        "Nutzer '{name}' {}.",
        if disabled { "gesperrt" } else { "entsperrt" }
    );
    Ok(())
}

pub fn user_roles(
    path: &Path,
    name: &str,
    set: Option<&[String]>,
    add: &[String],
    remove: &[String],
) -> Result<()> {
    let cfg = Config::load(path)?;
    let user = cfg
        .users
        .get(name)
        .with_context(|| format!("Nutzer '{name}' existiert nicht"))?;
    let mut roles = match set {
        Some(s) => clean_roles(s),
        None => user.roles.clone(),
    };
    for r in clean_roles(add) {
        if !roles.contains(&r) {
            roles.push(r);
        }
    }
    let remove = clean_roles(remove);
    roles.retain(|r| !remove.contains(r));

    if set.is_some() || !add.is_empty() || !remove.is_empty() {
        let mut doc = load_doc(path)?;
        user_table(&mut doc, name)?.insert("roles", value(string_array(&roles)));
        save_doc(path, &doc)?;
    }
    println!("{name}: [{}]", roles.join(", "));
    Ok(())
}

pub fn user_list(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    if cfg.users.is_empty() {
        println!("(keine Nutzer)");
    }
    for (name, u) in &cfg.users {
        let flag = if u.disabled { "  [gesperrt]" } else { "" };
        println!("{name}  [{}]{flag}", u.roles.join(", "));
    }
    Ok(())
}

// ---------------------------------------------------------------- Redirects

fn redirects(doc: &mut DocumentMut) -> Result<&mut Array> {
    if !doc.contains_key("allowed_redirects") {
        doc.insert("allowed_redirects", value(Array::new()));
    }
    doc["allowed_redirects"]
        .as_array_mut()
        .context("`allowed_redirects` muss eine Liste sein")
}

/// One URL per line so the file stays readable.
fn format_multiline(arr: &mut Array) {
    for v in arr.iter_mut() {
        v.decor_mut().set_prefix("\n  ");
        v.decor_mut().set_suffix("");
    }
    arr.set_trailing("\n");
    arr.set_trailing_comma(!arr.is_empty());
}

pub fn redirect_add(path: &Path, url: &str) -> Result<()> {
    check_redirect_url(url)?;
    let mut doc = load_doc(path)?;
    let arr = redirects(&mut doc)?;
    if arr.iter().any(|v| v.as_str() == Some(url)) {
        bail!("'{url}' ist bereits erlaubt");
    }
    arr.push(url);
    format_multiline(arr);
    save_doc(path, &doc)?;
    println!("Redirect '{url}' hinzugefügt.");
    Ok(())
}

pub fn redirect_remove(path: &Path, url: &str) -> Result<()> {
    let mut doc = load_doc(path)?;
    let arr = redirects(&mut doc)?;
    let before = arr.len();
    arr.retain(|v| v.as_str() != Some(url));
    if arr.len() == before {
        bail!("'{url}' ist nicht in der Liste");
    }
    format_multiline(arr);
    save_doc(path, &doc)?;
    println!("Redirect '{url}' entfernt.");
    Ok(())
}

pub fn redirect_list(path: &Path) -> Result<()> {
    let cfg = Config::load(path)?;
    if cfg.allowed_redirects.is_empty() {
        println!("(keine Redirects)");
    }
    for r in &cfg.allowed_redirects {
        println!("{r}");
    }
    Ok(())
}
