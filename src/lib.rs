//! LilVault - A secure, encrypted secrets management system for homelabs

// Clippy lints to prevent unsafe operations
#![warn(clippy::unwrap_used)]
#![warn(clippy::expect_used)]

pub mod audit;
pub mod cli;
pub mod crypto;
pub mod db;
pub mod error;
pub mod utils;
pub mod validation;

pub use error::{LilVaultError, Result};
