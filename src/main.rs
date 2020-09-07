use clap::{App, Arg, ArgMatches, SubCommand};
use curl::easy::{Easy, List};
use handlebars::Handlebars;
use log::{debug, LevelFilter};
use openssl::aes::{aes_ige, AesKey};
use openssl::base64;
use openssl::sha::Sha1;
use openssl::symm::Mode;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::env;
use std::fs::{metadata, read_dir, remove_file, OpenOptions};
use std::io::{stdin, BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process;
use std::time::{Duration, SystemTime};
use syslog::{BasicLogger, Facility, Formatter3164};
use url::form_urlencoded;

type DynError = Box<dyn std::error::Error>;

const COOKIE_TTL: u64 = 60 * 60 * 8;

include!(concat!(env!("OUT_DIR"), "/secret.rs"));

fn rand_str(len: usize) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        abcdefghijklmnopqrstuvwxyz\
                        0123456789)(*&^%$#@!~";
    let mut rng = rand::thread_rng();

    let password: String = (0..len)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    password
}

#[derive(Debug)]
struct Config {
    cache_dir: String,
    cookie_ttl: u64,
    gogs_url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self::new()
    }
}

impl Config {
    fn value_of(line: &str) -> String {
        let segs: Vec<&str> = line.split('=').collect();
        if segs.len() > 1 {
            segs[1].to_string()
        } else {
            "".into()
        }
    }

    fn new() -> Self {
        let mut cache_dir = "/var/cache/cgit-gogs-auth-filter".to_string();
        let mut cookie_ttl = COOKIE_TTL;
        let mut gogs_url = "https://127.0.0.1:3000".to_string();
        if let Ok(f) = OpenOptions::new().read(true).open("/etc/cgitrc") {
            let f = BufReader::new(f);
            for line in f.lines() {
                if let Ok(s) = line {
                    if s.starts_with("cgit-gogs-auth-filter.cache-dir") {
                        cache_dir = Self::value_of(&s);
                    } else if s.starts_with("cgit-gogs-auth-filter.cookie-ttl") {
                        cookie_ttl = Self::value_of(&s).parse::<u64>().unwrap_or(COOKIE_TTL);
                    } else if s.starts_with("cgit-gogs-auth-filter.gogs-url") {
                        gogs_url = Self::value_of(&s);
                    }
                }
            }
        }
        Self {
            cache_dir,
            cookie_ttl,
            gogs_url,
        }
    }
}

#[derive(Debug, Default, Deserialize, Serialize)]
struct Data {
    username: String,
    password: String,
    nonce: String,
}

impl Data {
    fn encrypt(plaintext: &[u8]) -> Vec<u8> {
        let mut iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                        \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let mut buffer = [0u8; 32];
        let mut encrypted: Vec<u8> = vec![];
        let key = AesKey::new_encrypt(SECRET_KEY).unwrap();
        for chunk in plaintext.chunks(32) {
            aes_ige(chunk, &mut buffer, &key, &mut iv, Mode::Encrypt);
            encrypted.extend_from_slice(&buffer);
        }
        encrypted
    }

    fn decrypt(encrypted: &[u8]) -> Vec<u8> {
        let mut iv = *b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F\
                        \x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1A\x1B\x1C\x1D\x1E\x1F";
        let mut buffer = [0u8; 32];
        let mut decrypted: Vec<u8> = vec![];
        let key = AesKey::new_decrypt(SECRET_KEY).unwrap();
        for chunk in encrypted.chunks(32) {
            aes_ige(chunk, &mut buffer, &key, &mut iv, Mode::Decrypt);
            decrypted.extend_from_slice(&buffer);
        }
        decrypted
    }

    pub fn new<T: ToString>(username: T, password: T, nonce: T) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            nonce: nonce.to_string(),
        }
    }

    pub fn from_file<P: AsRef<Path>>(path: P, encrypted: bool) -> Result<Self, DynError> {
        let mut file = OpenOptions::new().read(true).open(path)?;
        let mut buffer = Vec::new();
        let size = file.read_to_end(&mut buffer)?;
        if encrypted {
            let size = if size % 32 != 0 {
                ((size / 32) + 1) * 32
            } else {
                size
            };
            buffer.resize(size, 0);
            buffer = Self::decrypt(&buffer);
        }
        let plaintext = std::str::from_utf8(&buffer)?;
        toml::from_str(plaintext.trim_end_matches(char::from(0))).map_err(|e| e.into())
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P, encrypt: bool) {
        let plaintext = toml::to_string(self).unwrap();
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(path)
            .unwrap();
        if encrypt {
            let size = if plaintext.len() % 32 != 0 {
                ((plaintext.len() / 32) + 1) * 32
            } else {
                plaintext.len()
            };
            let mut buffer: Vec<u8> = vec![];
            buffer.extend_from_slice(plaintext.as_bytes());
            buffer.resize(size, 0);
            file.write_all(&Self::encrypt(&buffer)).unwrap();
        } else {
            file.write_all(plaintext.as_bytes()).unwrap();
        }
    }

    pub fn hash(&self) -> String {
        let toml = toml::to_string(self).unwrap();
        let mut hasher = Sha1::new();
        hasher.update(SECRET_KEY);
        hasher.update(toml.as_bytes());
        let hash = hasher.finish();
        hex::encode(hash)
    }
}

#[derive(Serialize)]
struct Meta<'a> {
    action: &'a str,
    redirect: &'a str,
}

// Verify username and password via gogs.
fn verify_login(cfg: &Config, data: &Data) -> Result<bool, DynError> {
    let mut dst = Vec::new();
    let mut easy = Easy::new();
    let mut list = List::new();
    let url = format!("{}/api/v1/users/{}/tokens", cfg.gogs_url, data.username);
    easy.url(&url)?;
    let basic_raw = format!("{}:{}", data.username, data.password);
    let basic_b64 = base64::encode_block(basic_raw.as_bytes());
    let auth_basic = format!("Authorization: Basic {}", basic_b64);
    list.append(&auth_basic)?;
    easy.http_headers(list)?;
    easy.ssl_verify_host(false)?;
    easy.ssl_verify_peer(false)?;
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            dst.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let code = easy.response_code()?;
    Ok(code == 200)
}

// Verify permission via gogs.
fn verify_perms(cfg: &Config, data: &Data, repo: &str) -> Result<(), DynError> {
    let mut dst = Vec::new();
    let mut easy = Easy::new();
    let mut list = List::new();
    let url = format!("{}/api/v1/repos/{}", cfg.gogs_url, repo);
    easy.url(&url)?;
    let basic_raw = format!("{}:{}", data.username, data.password);
    let basic_b64 = base64::encode_block(basic_raw.as_bytes());
    let auth_basic = format!("Authorization: Basic {}", basic_b64);
    list.append(&auth_basic)?;
    easy.http_headers(list)?;
    easy.ssl_verify_host(false)?;
    easy.ssl_verify_peer(false)?;
    {
        let mut transfer = easy.transfer();
        transfer.write_function(|data| {
            dst.extend_from_slice(data);
            Ok(data.len())
        })?;
        transfer.perform()?;
    }
    let code = easy.response_code()?;
    if code == 200 {
        Ok(())
    } else {
        Err("Unauthorized".into())
    }
}

// Processing the `authenticate-basic` called by cgit.
fn cmd_authenticate_basic<'a>(
    matches: &ArgMatches<'a>,
    cfg: Option<Config>,
) -> Result<(), DynError> {
    let cfg = cfg.unwrap_or_default();
    // Read `Authorization` header from env
    if let Ok(auth) = env::var("HTTP_AUTHORIZATION") {
        // Currently only support `Basic` authorization
        if !auth.starts_with("Basic ") {
            return Err("Only Http-Authorization Basic supported!".into());
        }
        let data: Data;
        let repo = matches.value_of("repo").unwrap_or("");
        // Remove `Basic ` prefix
        let (_, basic_b64) = auth.split_at(6);
        // Decode base64
        let decoded = base64::decode_block(&basic_b64)?;
        let basic_raw = std::str::from_utf8(&decoded)?;
        // Split username and password
        let fields: Vec<&str> = basic_raw.splitn(2, ':').collect();
        if fields.len() > 1 {
            data = Data::new(fields[0], fields[1], "");
        } else {
            data = Data::new(fields[0], "", "");
        }
        verify_perms(&cfg, &data, repo)
    } else {
        Err("Http-Authorization does not exists!".into())
    }
}

// Processing the `authenticate-cookie` called by cgit.
fn cmd_authenticate_cookie<'a>(
    matches: &ArgMatches<'a>,
    cfg: Option<Config>,
) -> Result<(), DynError> {
    // Load configurations.
    let cfg = cfg.unwrap_or_default();
    // Read stdin from upstream.
    let mut buffer = String::new();
    stdin().read_to_string(&mut buffer)?;
    // Get Http-Cookie header.
    let cookie = matches.value_of("http-cookie").unwrap_or("");
    if cookie.is_empty() {
        // Try Authenticate-Basic if header exists.
        return cmd_authenticate_basic(matches, Some(cfg));
    }
    // Find hash and nonce
    let mut cgitauth_b64 = String::new();
    let segs = cookie.split(';').map(|x| x.trim()).collect::<Vec<&str>>();
    for s in segs {
        if s.starts_with("cgitauth=") {
            let (_, val) = s.split_at(9);
            cgitauth_b64 = val.to_string();
            break;
        }
    }
    if cgitauth_b64.is_empty() {
        // Try Authenticate-Basic if header exists.
        return cmd_authenticate_basic(matches, Some(cfg));
    }
    // Decode the base64 encoded cookie.
    let decoded_bytes = base64::decode_block(&cgitauth_b64)?;
    let cgitauth_plain = std::str::from_utf8(&decoded_bytes)?;
    let list: Vec<&str> = cgitauth_plain.splitn(2, ':').collect();
    if list.len() < 2 {
        return Err("Nonce does not exists!".into());
    }
    // Check the encrypted cookie file.
    let path = Path::new(&cfg.cache_dir).join(list[0]);
    if !path.exists() {
        return Err("Cookie does not exists!".into());
    }
    // Check session timeout.
    let meta = metadata(&path)?;
    let modified = meta.modified()?;
    let elapsed = SystemTime::now().duration_since(modified)?;
    if elapsed > Duration::from_secs(cfg.cookie_ttl) {
        remove_file(&path)?;
        return Err("Cookie is timeout!".into());
    }
    // Load encrypted cookie file.
    let data = Data::from_file(&path, true)?;
    // Verify the nonce.
    if data.nonce != list[1] {
        return Err("Nonce is not matched!".into());
    }
    // Check repo permissions.
    let repo = matches.value_of("repo").unwrap_or("");
    if !repo.is_empty() {
        verify_perms(&cfg, &data, repo)?;
    }
    //
    Ok(())
}

// Processing the `authenticate-post` called by cgit.
fn cmd_authenticate_post<'a>(
    matches: &ArgMatches<'a>,
    cfg: Option<Config>,
) -> Result<(), DynError> {
    // Load configurations.
    let cfg = cfg.unwrap_or_default();
    // Read stdin from upstream.
    let mut buffer = String::new();
    stdin().read_to_string(&mut buffer)?;
    // Parsing user posted form.
    let mut data = Data::new("", "", &rand_str(6));
    let fields = form_urlencoded::parse(buffer.as_bytes());
    for f in fields {
        match f.0 {
            Cow::Borrowed("username") => {
                data.username = f.1.to_string();
            }
            Cow::Borrowed("password") => {
                data.password = f.1.to_string();
            }
            _ => {}
        }
    }
    // Authenticated via gogs.
    if verify_login(&cfg, &data).is_ok() {
        let hash = data.hash();
        let cgitauth = format!("{}:{}", hash, data.nonce);
        let cgitauth_b64 = base64::encode_block(cgitauth.as_bytes());
        let path = Path::new(&cfg.cache_dir).join(&hash);
        data.to_file(path, true);
        let is_secure = matches
            .value_of("https")
            .map_or(false, |x| matches!(x, "yes" | "on" | "1"));
        let domain = matches.value_of("http-host").unwrap_or("*");
        let location = matches
            .value_of("current-url")
            .unwrap_or("/")
            .split('?')
            .next()
            .unwrap();
        let cookie_suffix = if is_secure { "; secure" } else { "" };
        println!("Status: 302 Redirect");
        println!("Cache-Control: no-cache, no-store");
        println!("Location: {}", location);
        println!(
            "Set-Cookie: cgitauth={}; Domain={}; Max-Age={}; HttpOnly{}",
            cgitauth_b64, domain, cfg.cookie_ttl, cookie_suffix
        );
    } else {
        println!("Status: 401 Unauthorized");
        println!("Cache-Control: no-cache, no-store");
    }
    println!();
    Ok(())
}

// Processing the `body` called by cgit.
fn cmd_body<'a>(matches: &ArgMatches<'a>, _cfg: Option<Config>) {
    let source = include_str!("login-template.html");
    let handlebars = Handlebars::new();
    let meta = Meta {
        action: matches.value_of("login-url").unwrap_or(""),
        redirect: matches.value_of("current-url").unwrap_or(""),
    };
    handlebars
        .render_template_to_write(source, &meta, std::io::stdout())
        .unwrap();
}

// Processing the `body` called by cron.
fn cmd_expire<'a>(_matches: &ArgMatches<'a>, cfg: Option<Config>) {
    let cfg = cfg.unwrap_or_default();
    for entry in read_dir(cfg.cache_dir).unwrap() {
        let entry = entry.unwrap();
        if let Ok(file_type) = entry.file_type() {
            if !file_type.is_file() {
                continue;
            }
        }
        if let Ok(meta) = entry.metadata() {
            if !meta.is_file() {
                continue;
            }
            if let Ok(time) = meta.modified() {
                let elapsed = SystemTime::now().duration_since(time).unwrap();
                if elapsed > Duration::from_secs(cfg.cookie_ttl) {
                    println!(
                        "Remove {:?} > {:?}, {:?}",
                        elapsed,
                        Duration::from_secs(cfg.cookie_ttl),
                        entry.path()
                    );
                    remove_file(&entry.path()).unwrap();
                }
            }
        }
    }
}

fn main() {
    if cfg!(debug_assertions) {
        let formatter = Formatter3164 {
            facility: Facility::LOG_USER,
            hostname: None,
            process: "cgit-gogs-auth-filter".into(),
            pid: process::id() as i32,
        };

        let logger = syslog::unix(formatter).expect("could not connect to syslog");
        if let Ok(()) = log::set_boxed_logger(Box::new(BasicLogger::new(logger))) {
            log::set_max_level(LevelFilter::Debug);
        }

        // Prints each argument on a separate line
        for (nth, argument) in env::args().enumerate() {
            debug!("[{}]={}", nth, argument);
        }
    } else {
        log::set_max_level(LevelFilter::Off);
    }

    // Sub-arguments for each command, see cgi defines.
    let sub_args = &[
        Arg::with_name("http-cookie").required(true),
        Arg::with_name("request-method").required(true),
        Arg::with_name("query-string").required(true),
        Arg::with_name("http-referer").required(true),
        Arg::with_name("path-info").required(true),
        Arg::with_name("http-host").required(true),
        Arg::with_name("https").required(true),
        Arg::with_name("repo").required(true),
        Arg::with_name("page").required(true),
        Arg::with_name("current-url").required(true),
        Arg::with_name("login-url").required(true),
    ];

    let matches = App::new("Gogs Authentication Filter for cgit")
        .version(env!("CARGO_PKG_VERSION"))
        .author("Varphone Wong <varphone@qq.com>")
        .about("https://github.com/varphone/cgit-gogs-auth-filter")
        .subcommand(
            SubCommand::with_name("authenticate-cookie")
                .about("Processing authenticated cookie")
                .args(sub_args),
        )
        .subcommand(
            SubCommand::with_name("authenticate-post")
                .about("Processing posted username and password")
                .args(sub_args),
        )
        .subcommand(
            SubCommand::with_name("body")
                .about("Return the login form")
                .args(sub_args),
        )
        .subcommand(SubCommand::with_name("expire").about("Check and clean all expired cookies"))
        .get_matches();

    // Load filter configurations
    let cfg = Config::new();

    match matches.subcommand() {
        ("authenticate-cookie", Some(matches)) => {
            if cmd_authenticate_cookie(matches, Some(cfg)).is_ok() {
                std::process::exit(1);
            } else {
                std::process::exit(0);
            }
        }
        ("authenticate-post", Some(matches)) => {
            cmd_authenticate_post(matches, Some(cfg)).unwrap();
        }
        ("body", Some(matches)) => {
            cmd_body(matches, Some(cfg));
        }
        ("expire", Some(matches)) => {
            cmd_expire(matches, Some(cfg));
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto() {
        let plaintext = [1u8; 32];
        let encrypted = Data::encrypt(&plaintext);
        let decrypted = Data::decrypt(&encrypted);
        assert_eq!(&plaintext, &decrypted[0..32]);
    }

    #[test]
    fn test_base64() {
        let encoded = base64::encode_block(b"Aladdin:open sesame");
        let decoded = base64::decode_block(&encoded);
        assert_eq!(encoded, "QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
        assert!(decoded.is_ok());
        assert_eq!(decoded.unwrap(), b"Aladdin:open sesame");
    }
}
