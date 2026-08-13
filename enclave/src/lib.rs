//! Rust implementation of the sekisho attested AI gateway enclave.
//!
//! See `docs/SPEC.md` §4 for the contract this crate implements.

#![forbid(unsafe_code)]

pub mod auth;
pub mod canonical;
pub mod config;
pub mod policy;
pub mod providers;
pub mod receipt;
pub mod server;

pub use config::AppConfig;
pub use server::{app, serve};
