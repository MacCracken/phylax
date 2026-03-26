//! Phylax — AI-native threat detection engine for AGNOS.
//!
//! Provides YARA rule matching, entropy analysis, magic bytes detection,
//! polyglot file identification, PE/ELF binary parsing, string extraction,
//! and daimon/hoosh AI integration.

pub mod ai;
pub mod analyze;
#[cfg(feature = "bote")]
pub mod bote_tools;
pub mod daimon;
pub mod elf;
pub mod error;
pub mod hoosh;
pub mod pe;
pub mod quarantine;
pub mod queue;
pub mod report;
pub mod strings;
pub mod types;
pub mod watch;
pub mod yara;
pub mod yara_parser;
