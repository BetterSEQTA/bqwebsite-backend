use std::sync::OnceLock;

// Define the OnceLock at module level
pub static ENV_INITIALIZED: OnceLock<()> = OnceLock::new();

// Function to initialize environment variables
pub fn initialize_env() -> &'static () {
    ENV_INITIALIZED.get_or_init(|| {
        dotenvy::dotenv().ok();
        ()
    })
}