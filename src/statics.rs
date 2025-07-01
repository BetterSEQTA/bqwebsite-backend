use std::{sync::OnceLock};

use regex::Regex;

// Define the OnceLock at module level
pub static ENV_INITIALIZED: OnceLock<()> = OnceLock::new();
pub static EMAIL_REGEX: OnceLock<Regex> = OnceLock::new();
pub static USERNAME_REGEX: OnceLock<Regex> = OnceLock::new();

// Function to initialize environment variables
pub fn initialize_env() -> &'static () {
    ENV_INITIALIZED.get_or_init(|| {
        dotenvy::dotenv().ok();
        ()
    })
}

pub fn initialize_regex() -> () {
    EMAIL_REGEX.get_or_init(|| {
        regex::Regex::new(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)").expect("EMAIL_REGEX must compile")
    });

    USERNAME_REGEX.get_or_init(|| {
        regex::Regex::new(r"^[a-zA-Z0-9_.-]{3,32}$").expect("USERNAME_REGEX must compile")
    });
    ()

}