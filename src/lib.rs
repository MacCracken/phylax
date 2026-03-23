//! Phylax — AI-native threat detection engine for AGNOS.
//!
//! Provides YARA rule matching, entropy analysis, magic bytes detection,
//! polyglot file identification, and daimon/hoosh AI integration.

pub mod ai;
pub mod analyze;
pub mod core;
pub mod daimon;
pub mod error;
pub mod yara;
