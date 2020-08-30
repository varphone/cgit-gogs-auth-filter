use rand::Rng;
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::PathBuf;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                        abcdefghijklmnopqrstuvwxyz\
                        0123456789)(*&^%$#@!~";
const PASSWORD_LEN: usize = 16;

fn rand_str() -> String {
    let mut rng = rand::thread_rng();

    let password: String = (0..PASSWORD_LEN)
        .map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();

    password
}

type DynError = Box<dyn std::error::Error>;

fn main() -> Result<(), DynError> {
    println!("cargo:rerun-if-changed=build.rs");
    let secret_key = rand_str();
    let out_path = PathBuf::from(env::var("OUT_DIR")?);
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(out_path.join("secret.rs"))?;
    write!(file, "const SECRET_KEY: &[u8] = b\"{}\";", secret_key)?;
    Ok(())
}
