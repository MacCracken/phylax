//! Phylax — AI-native threat detection engine for AGNOS.
//!
//! Provides YARA rule matching, entropy analysis, magic bytes detection,
//! polyglot file identification, PE/ELF binary parsing, string extraction,
//! and daimon/hoosh AI integration.

pub mod ai;
pub mod analyze;
pub mod core;
pub mod daimon;
pub mod elf;
pub mod error;
pub mod pe;
pub mod quarantine;
pub mod queue;
pub mod report;
pub mod strings;
pub mod yara;
