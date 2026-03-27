//! PE (Portable Executable) header parsing.
//!
//! Parses DOS MZ header, PE signature, COFF header, optional header,
//! section table, and import/export directory entries.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Maximum number of sections to parse (PE spec allows up to 96).
const MAX_SECTIONS: usize = 96;
/// Maximum number of import directory entries to parse.
const MAX_IMPORTS: usize = 256;
/// Maximum number of exported function names to parse.
const MAX_EXPORTS: usize = 1024;

/// An imported function: DLL name + function name or ordinal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeImport {
    /// DLL name (e.g. "kernel32.dll").
    pub dll: String,
    /// Function name (e.g. "LoadLibraryA") or ordinal as string.
    pub function: String,
}

/// Parsed PE file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeInfo {
    /// Machine architecture.
    pub machine: PeMachine,
    /// Number of sections.
    pub num_sections: u16,
    /// Timestamp from COFF header (Unix epoch).
    pub timestamp: u32,
    /// Whether the file is a DLL.
    pub is_dll: bool,
    /// Whether the file is 64-bit (PE32+).
    pub is_64bit: bool,
    /// Entry point RVA.
    pub entry_point: u32,
    /// Parsed section headers.
    pub sections: Vec<PeSection>,
    /// Imported DLL names.
    pub imports: Vec<String>,
    /// Detailed import table: (DLL, function) pairs for imphash computation.
    pub import_functions: Vec<PeImport>,
    /// Exported function names.
    pub exports: Vec<String>,
    /// Whether TLS callbacks are present (anti-debug / pre-entrypoint execution).
    pub has_tls_callbacks: bool,
    /// PDB debug path (from debug directory), if present.
    pub pdb_path: Option<String>,
    /// Rich header entries (compiler/linker tool IDs), if present.
    pub rich_entries: Vec<RichEntry>,
    /// Resources extracted from the resource directory.
    pub resources: Vec<PeResource>,
    /// Authenticode certificate info, if present.
    pub certificate: Option<PeCertificate>,
}

/// PE Authenticode certificate information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeCertificate {
    /// Certificate table file offset.
    pub offset: u32,
    /// Certificate table total size.
    pub size: u32,
    /// Whether the certificate is present (non-zero size).
    pub present: bool,
}

/// A PE resource entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeResource {
    /// Resource type ID (e.g. 3=ICON, 6=STRING, 16=VERSION, 24=MANIFEST).
    pub type_id: u32,
    /// Human-readable type name.
    pub type_name: String,
    /// Resource size in bytes.
    pub size: u32,
    /// File offset of the resource data.
    pub offset: u32,
}

/// A Rich header entry — identifies a build tool and its usage count.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RichEntry {
    /// Tool ID (build number).
    pub tool_id: u16,
    /// Product/compiler identifier.
    pub product_id: u16,
    /// Number of times this tool was used.
    pub count: u32,
}

impl RichEntry {
    /// Look up a human-readable name for this tool.
    #[must_use]
    pub fn tool_name(&self) -> &'static str {
        rich_product_name(self.product_id)
    }
}

/// Look up a human-readable product name from a Rich header product ID.
///
/// Based on the well-known product ID table from the MSVC toolchain.
#[must_use]
pub fn rich_product_name(product_id: u16) -> &'static str {
    match product_id {
        // Visual Studio version by product ID ranges
        0 => "[padding]",
        1 => "Import",
        2..=6 => "VS6.0 (1998)",
        7..=9 => "VS2002 (7.0)",
        10..=13 => "VS2003 (7.1)",
        14..=39 => "VS2005 (8.0)",
        40..=83 => "VS2008 (9.0)",
        84..=146 => "VS2010 (10.0)",
        147..=169 => "VS2012 (11.0)",
        170..=199 => "VS2013 (12.0)",
        200..=219 => "VS2015 (14.0)",
        220..=260 => "VS2017 (14.1)",
        261..=270 => "VS2019 (14.2)",
        271..=280 => "VS2022 (14.3)",
        281..=300 => "VS2022 (14.4+)",
        _ => "Unknown",
    }
}

/// PE machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum PeMachine {
    I386,
    Amd64,
    Arm,
    Arm64,
    Unknown(u16),
}

impl fmt::Display for PeMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::I386 => write!(f, "i386"),
            Self::Amd64 => write!(f, "AMD64"),
            Self::Arm => write!(f, "ARM"),
            Self::Arm64 => write!(f, "ARM64"),
            Self::Unknown(v) => write!(f, "unknown(0x{v:04x})"),
        }
    }
}

/// A PE section header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    /// Section name (up to 8 bytes, null-trimmed).
    pub name: String,
    /// Virtual size.
    pub virtual_size: u32,
    /// Virtual address (RVA).
    pub virtual_address: u32,
    /// Size of raw data on disk.
    pub raw_data_size: u32,
    /// File offset of raw data.
    pub raw_data_offset: u32,
    /// Section characteristics flags.
    pub characteristics: u32,
}

impl PeSection {
    /// Whether this section is executable.
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Whether this section is writable.
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Whether this section contains code.
    #[must_use]
    pub fn contains_code(&self) -> bool {
        self.characteristics & 0x0000_0020 != 0
    }
}

/// Read a little-endian u16 from a byte slice at the given offset.
#[inline]
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian u32 from a byte slice at the given offset.
#[inline]
fn read_u32_le(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// Read a null-terminated ASCII string (up to `max_len` bytes) at offset.
fn read_ascii(data: &[u8], offset: usize, max_len: usize) -> String {
    let end = (offset + max_len).min(data.len());
    if offset >= data.len() {
        return String::new();
    }
    let slice = &data[offset..end];
    let nul = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    String::from_utf8_lossy(&slice[..nul]).into_owned()
}

/// Try to parse PE headers from raw file data.
///
/// Returns `None` if the data is not a valid PE file.
#[must_use]
pub fn parse_pe(data: &[u8]) -> Option<PeInfo> {
    // DOS MZ header check
    if data.len() < 64 || data[0] != 0x4d || data[1] != 0x5a {
        return None;
    }

    // e_lfanew: offset to PE signature at offset 0x3C
    let pe_offset = read_u32_le(data, 0x3C)? as usize;

    // PE signature: "PE\0\0"
    if data.len() < pe_offset + 4 {
        return None;
    }
    if data[pe_offset..pe_offset + 4] != [0x50, 0x45, 0x00, 0x00] {
        return None;
    }

    let coff_offset = pe_offset + 4;
    if data.len() < coff_offset + 20 {
        return None;
    }

    // COFF header fields
    let machine_raw = read_u16_le(data, coff_offset)?;
    let machine = match machine_raw {
        0x014c => PeMachine::I386,
        0x8664 => PeMachine::Amd64,
        0x01c0 => PeMachine::Arm,
        0xaa64 => PeMachine::Arm64,
        v => PeMachine::Unknown(v),
    };

    let num_sections = read_u16_le(data, coff_offset + 2)?;
    let timestamp = read_u32_le(data, coff_offset + 4)?;
    let optional_header_size = read_u16_le(data, coff_offset + 16)? as usize;
    let characteristics = read_u16_le(data, coff_offset + 18)?;
    let is_dll = characteristics & 0x2000 != 0;

    // Optional header
    let opt_offset = coff_offset + 20;
    if data.len() < opt_offset + 2 {
        return None;
    }

    let magic = read_u16_le(data, opt_offset)?;
    let is_64bit = magic == 0x020b; // PE32+ = 0x020b, PE32 = 0x010b

    let entry_point = read_u32_le(data, opt_offset + 16).unwrap_or(0);

    // Parse section table (cap to prevent excessive allocation from crafted headers)
    let section_table_offset = opt_offset + optional_header_size;
    let capped_sections = (num_sections as usize).min(MAX_SECTIONS);
    let mut sections = Vec::with_capacity(capped_sections);

    for i in 0..capped_sections {
        let sec_offset = section_table_offset + i * 40;
        if data.len() < sec_offset + 40 {
            break;
        }

        let name = read_ascii(data, sec_offset, 8);
        let virtual_size = read_u32_le(data, sec_offset + 8).unwrap_or(0);
        let virtual_address = read_u32_le(data, sec_offset + 12).unwrap_or(0);
        let raw_data_size = read_u32_le(data, sec_offset + 16).unwrap_or(0);
        let raw_data_offset = read_u32_le(data, sec_offset + 20).unwrap_or(0);
        let sec_characteristics = read_u32_le(data, sec_offset + 36).unwrap_or(0);

        sections.push(PeSection {
            name,
            virtual_size,
            virtual_address,
            raw_data_size,
            raw_data_offset,
            characteristics: sec_characteristics,
        });
    }

    // Parse import directory
    let (imports, import_functions) = parse_pe_imports(data, opt_offset, is_64bit);

    // Parse export directory
    let exports = parse_pe_exports(data, opt_offset, is_64bit);

    // TLS callback detection (data directory entry #9)
    let has_tls_callbacks = detect_tls_callbacks(data, opt_offset, is_64bit);

    // Debug directory / PDB path (data directory entry #6)
    let pdb_path = parse_debug_directory(data, opt_offset, is_64bit);

    // Rich header (between DOS stub and PE signature)
    let rich_entries = parse_rich_header(data, pe_offset);

    // Resource directory (data directory entry #2)
    let resources = parse_pe_resources(data, opt_offset, is_64bit);

    // Certificate table (data directory entry #4) — uses file offsets, not RVAs
    let certificate = parse_pe_certificate(data, opt_offset, is_64bit);

    Some(PeInfo {
        machine,
        num_sections,
        timestamp,
        is_dll,
        is_64bit,
        entry_point,
        sections,
        imports,
        import_functions,
        exports,
        has_tls_callbacks,
        pdb_path,
        rich_entries,
        resources,
        certificate,
    })
}

/// Maximum number of functions to resolve per DLL.
const MAX_FUNCTIONS_PER_DLL: usize = 512;

/// Parse import directory table to extract DLL names and function-level imports.
fn parse_pe_imports(
    data: &[u8],
    opt_offset: usize,
    is_64bit: bool,
) -> (Vec<String>, Vec<PeImport>) {
    let mut dll_names = Vec::new();
    let mut functions = Vec::new();

    // Import directory is data directory entry #1
    let dd_offset = if is_64bit {
        opt_offset + 120
    } else {
        opt_offset + 104
    };

    let import_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return (dll_names, functions),
    };

    let file_offset = match rva_to_offset(data, opt_offset, import_rva) {
        Some(off) => off,
        None => return (dll_names, functions),
    };

    // Each import directory entry is 20 bytes, terminated by an all-zero entry
    let mut idx = file_offset;
    for _ in 0..MAX_IMPORTS {
        if data.len() < idx + 20 {
            break;
        }

        let name_rva = match read_u32_le(data, idx + 12) {
            Some(rva) if rva > 0 => rva,
            _ => break,
        };

        let dll_name = if let Some(name_offset) = rva_to_offset(data, opt_offset, name_rva) {
            let name = read_ascii(data, name_offset, 256);
            if name.is_empty() {
                idx += 20;
                continue;
            }
            dll_names.push(name.clone());
            name
        } else {
            idx += 20;
            continue;
        };

        // Parse Import Lookup Table (ILT) / Import Name Table (INT)
        // OriginalFirstThunk (ILT) at offset +0, FirstThunk (INT) at offset +16
        let ilt_rva = read_u32_le(data, idx).unwrap_or(0);
        let thunk_rva = if ilt_rva > 0 {
            ilt_rva
        } else {
            read_u32_le(data, idx + 16).unwrap_or(0)
        };

        if let Some(thunk_offset) = rva_to_offset(data, opt_offset, thunk_rva) {
            let entry_size = if is_64bit { 8 } else { 4 };
            let ordinal_flag: u64 = if is_64bit { 1u64 << 63 } else { 1u64 << 31 };

            let mut t = thunk_offset;
            for _ in 0..MAX_FUNCTIONS_PER_DLL {
                if data.len() < t + entry_size {
                    break;
                }

                let entry = if is_64bit {
                    match data.get(t..t + 8) {
                        Some(b) => {
                            u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
                        }
                        None => break,
                    }
                } else {
                    match data.get(t..t + 4) {
                        Some(b) => u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64,
                        None => break,
                    }
                };

                if entry == 0 {
                    break;
                }

                if entry & ordinal_flag != 0 {
                    // Import by ordinal
                    let ordinal = (entry & 0xFFFF) as u16;
                    functions.push(PeImport {
                        dll: dll_name.clone(),
                        function: format!("ord{ordinal}"),
                    });
                } else {
                    // Import by name: entry is RVA to hint/name table entry
                    let hint_rva = (entry & 0x7FFFFFFF) as u32;
                    if let Some(hint_offset) = rva_to_offset(data, opt_offset, hint_rva) {
                        // Skip 2-byte hint, read name
                        let func_name = read_ascii(data, hint_offset + 2, 256);
                        if !func_name.is_empty() {
                            functions.push(PeImport {
                                dll: dll_name.clone(),
                                function: func_name,
                            });
                        }
                    }
                }

                t += entry_size;
            }
        }

        idx += 20;
    }

    (dll_names, functions)
}

/// Compute the import hash (imphash) from a list of PE imports.
///
/// Uses the standard imphash algorithm (ordered, lowercased, comma-separated
/// "dll.function" strings with the DLL extension stripped), but hashes with
/// SHA-256 (truncated to 128 bits) instead of MD5 to avoid an MD5 dependency.
///
/// Note: this produces different hashes than pefile/VirusTotal (which use MD5).
/// Use for internal clustering and comparison, not for cross-tool lookups.
#[must_use]
pub fn compute_imphash(imports: &[PeImport]) -> String {
    use sha2::{Digest, Sha256};
    use std::fmt::Write;

    if imports.is_empty() {
        return String::new();
    }

    let entries: Vec<String> = imports
        .iter()
        .map(|imp| {
            // Strip .dll extension from DLL name
            let dll = imp.dll.to_lowercase();
            let dll = dll.strip_suffix(".dll").unwrap_or(&dll);
            format!("{}.{}", dll, imp.function.to_lowercase())
        })
        .collect();

    let joined = entries.join(",");

    // Use SHA-256 instead of MD5 (more secure, no md5 dependency needed)
    let mut hasher = Sha256::new();
    hasher.update(joined.as_bytes());
    let result = hasher.finalize();

    // Return first 16 bytes (128 bits) as hex for MD5-compatible length
    let mut s = String::with_capacity(32);
    for &b in &result[..16] {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parse export directory to extract function names.
fn parse_pe_exports(data: &[u8], opt_offset: usize, is_64bit: bool) -> Vec<String> {
    let mut exports = Vec::new();

    // Export directory is data directory entry #0
    let dd_offset = if is_64bit {
        opt_offset + 112
    } else {
        opt_offset + 96
    };

    let export_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return exports,
    };

    let export_offset = match rva_to_offset(data, opt_offset, export_rva) {
        Some(off) => off,
        None => return exports,
    };

    // Export directory: number of names at offset +24, name pointer table RVA at +32
    let num_names = match read_u32_le(data, export_offset + 24) {
        Some(n) => n as usize,
        None => return exports,
    };

    let name_table_rva = match read_u32_le(data, export_offset + 32) {
        Some(rva) => rva,
        None => return exports,
    };

    let name_table_offset = match rva_to_offset(data, opt_offset, name_table_rva) {
        Some(off) => off,
        None => return exports,
    };

    for i in 0..num_names.min(MAX_EXPORTS) {
        // safety limit
        let name_rva = match read_u32_le(data, name_table_offset + i * 4) {
            Some(rva) => rva,
            None => break,
        };

        if let Some(name_offset) = rva_to_offset(data, opt_offset, name_rva) {
            let name = read_ascii(data, name_offset, 256);
            if !name.is_empty() {
                exports.push(name);
            }
        }
    }

    exports
}

/// Convert an RVA to a file offset using the section table.
fn rva_to_offset(data: &[u8], opt_offset: usize, rva: u32) -> Option<usize> {
    // Read COFF header to find section table
    let coff_offset = opt_offset - 20; // COFF header is 20 bytes before optional header
    let num_sections = read_u16_le(data, coff_offset + 2)? as usize;
    let optional_header_size = read_u16_le(data, coff_offset + 16)? as usize;
    let section_table_offset = opt_offset + optional_header_size;

    for i in 0..num_sections {
        let sec_offset = section_table_offset + i * 40;
        if data.len() < sec_offset + 40 {
            break;
        }

        let vaddr = read_u32_le(data, sec_offset + 12)?;
        let raw_size = read_u32_le(data, sec_offset + 16)?;
        let raw_offset = read_u32_le(data, sec_offset + 20)?;

        let vaddr_end = match vaddr.checked_add(raw_size) {
            Some(end) => end,
            None => continue,
        };
        if rva >= vaddr && rva < vaddr_end {
            return Some((rva - vaddr + raw_offset) as usize);
        }
    }

    None
}

// ---------------------------------------------------------------------------
// TLS callback detection
// ---------------------------------------------------------------------------

/// Check if the PE has TLS callbacks (data directory entry #9).
fn detect_tls_callbacks(data: &[u8], opt_offset: usize, is_64bit: bool) -> bool {
    // TLS directory is data directory entry #9
    // PE32: base offset 96 + 9*8 = 168; PE32+: base offset 112 + 9*8 = 184
    let dd_offset = if is_64bit {
        opt_offset + 184
    } else {
        opt_offset + 168
    };

    let tls_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return false,
    };

    let tls_size = read_u32_le(data, dd_offset + 4).unwrap_or(0);
    if tls_size == 0 {
        return false;
    }

    // TLS directory exists — check if callback table pointer is non-zero
    if let Some(tls_offset) = rva_to_offset(data, opt_offset, tls_rva) {
        // AddressOfCallBacks is at offset 12 (PE32) or 24 (PE32+) in the TLS directory
        let cb_field_offset = if is_64bit {
            tls_offset + 24
        } else {
            tls_offset + 12
        };

        let callbacks_ptr = if is_64bit {
            data.get(cb_field_offset..cb_field_offset + 8)
                .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
                .unwrap_or(0)
        } else {
            read_u32_le(data, cb_field_offset).unwrap_or(0) as u64
        };

        return callbacks_ptr != 0;
    }

    false
}

// ---------------------------------------------------------------------------
// Debug directory / PDB path
// ---------------------------------------------------------------------------

/// Extract PDB path from the PE debug directory (data directory entry #6).
fn parse_debug_directory(data: &[u8], opt_offset: usize, is_64bit: bool) -> Option<String> {
    // Debug directory is data directory entry #6
    let dd_offset = if is_64bit {
        opt_offset + 160
    } else {
        opt_offset + 144
    };

    let debug_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return None,
    };

    let debug_offset = rva_to_offset(data, opt_offset, debug_rva)?;

    // Debug directory entry: Type is at offset +12 (u32)
    // IMAGE_DEBUG_TYPE_CODEVIEW = 2
    let debug_type = read_u32_le(data, debug_offset + 12)?;
    if debug_type != 2 {
        return None;
    }

    // PointerToRawData at offset +24
    let raw_offset = read_u32_le(data, debug_offset + 24)? as usize;

    // CodeView header: check for "RSDS" signature
    if data.len() < raw_offset + 24 {
        return None;
    }
    if data.get(raw_offset..raw_offset + 4)? != b"RSDS" {
        return None;
    }

    // PDB path starts at offset +24 from RSDS header
    let path = read_ascii(data, raw_offset + 24, 260);
    if path.is_empty() { None } else { Some(path) }
}

// ---------------------------------------------------------------------------
// Rich header parsing
// ---------------------------------------------------------------------------

/// Parse the Rich header from between the DOS stub and PE signature.
///
/// The Rich header is XOR-encrypted with a key found at the "Rich" marker.
fn parse_rich_header(data: &[u8], pe_offset: usize) -> Vec<RichEntry> {
    let mut entries = Vec::new();

    // Search for "Rich" marker between DOS header and PE signature
    let search_end = pe_offset.min(data.len());
    let rich_pos = (0x80..search_end).find(|&i| data.get(i..i + 4) == Some(b"Rich"));

    let rich_pos = match rich_pos {
        Some(p) => p,
        None => return entries,
    };

    // XOR key is the 4 bytes after "Rich"
    let key = match read_u32_le(data, rich_pos + 4) {
        Some(k) => k,
        None => return entries,
    };

    // Search backwards for "DanS" marker (XOR'd with key)
    let dans_marker = 0x536E6144u32 ^ key; // "DanS" XOR'd
    let dans_pos = (0x80..rich_pos)
        .rev()
        .find(|&i| read_u32_le(data, i) == Some(dans_marker));

    let dans_pos = match dans_pos {
        Some(p) => p,
        None => return entries,
    };

    // Entries start after DanS + 3 padding DWORDs (each XOR'd with key)
    let entries_start = dans_pos + 16; // DanS(4) + 3 * padding(4) = 16

    // Each entry is 8 bytes: tool_id(2) + product_id(2) (as u32) + count(4)
    let mut i = entries_start;
    while i + 8 <= rich_pos {
        let val1 = read_u32_le(data, i).unwrap_or(0) ^ key;
        let val2 = read_u32_le(data, i + 4).unwrap_or(0) ^ key;

        let tool_id = (val1 & 0xFFFF) as u16;
        let product_id = (val1 >> 16) as u16;
        let count = val2;

        if tool_id != 0 || product_id != 0 {
            entries.push(RichEntry {
                tool_id,
                product_id,
                count,
            });
        }
        i += 8;
    }

    entries
}

// ---------------------------------------------------------------------------
// Resource directory parsing
// ---------------------------------------------------------------------------

/// Well-known PE resource type IDs.
fn resource_type_name(id: u32) -> &'static str {
    match id {
        1 => "CURSOR",
        2 => "BITMAP",
        3 => "ICON",
        4 => "MENU",
        5 => "DIALOG",
        6 => "STRING",
        7 => "FONTDIR",
        8 => "FONT",
        9 => "ACCELERATOR",
        10 => "RCDATA",
        11 => "MESSAGETABLE",
        12 => "GROUP_CURSOR",
        14 => "GROUP_ICON",
        16 => "VERSION",
        24 => "MANIFEST",
        _ => "UNKNOWN",
    }
}

/// Parse the PE resource directory (data directory entry #2).
fn parse_pe_resources(data: &[u8], opt_offset: usize, is_64bit: bool) -> Vec<PeResource> {
    const MAX_RESOURCES: usize = 512;

    // Resource directory is data directory entry #2
    let dd_offset = if is_64bit {
        opt_offset + 136
    } else {
        opt_offset + 120
    };

    let rsrc_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return Vec::new(),
    };

    let rsrc_base = match rva_to_offset(data, opt_offset, rsrc_rva) {
        Some(off) => off,
        None => return Vec::new(),
    };

    let mut resources = Vec::new();

    // Parse root directory: each entry is a resource type
    let num_named = read_u16_le(data, rsrc_base + 12).unwrap_or(0) as usize;
    let num_id = read_u16_le(data, rsrc_base + 14).unwrap_or(0) as usize;
    let total = (num_named + num_id).min(64);

    for i in 0..total {
        let entry_off = rsrc_base + 16 + i * 8;
        if data.len() < entry_off + 8 {
            break;
        }

        let type_id = read_u32_le(data, entry_off).unwrap_or(0) & 0x7FFFFFFF;
        let offset_or_dir = read_u32_le(data, entry_off + 4).unwrap_or(0);

        // If high bit set, it points to a subdirectory
        if offset_or_dir & 0x80000000 != 0 {
            let subdir_off = rsrc_base + (offset_or_dir & 0x7FFFFFFF) as usize;
            // Parse second-level directory (name/ID entries)
            let sub_named = read_u16_le(data, subdir_off + 12).unwrap_or(0) as usize;
            let sub_id = read_u16_le(data, subdir_off + 14).unwrap_or(0) as usize;
            let sub_total = (sub_named + sub_id).min(64);

            for j in 0..sub_total {
                let sub_entry = subdir_off + 16 + j * 8;
                if data.len() < sub_entry + 8 {
                    break;
                }
                let sub_offset = read_u32_le(data, sub_entry + 4).unwrap_or(0);

                // Third level: language entries
                if sub_offset & 0x80000000 != 0 {
                    let lang_dir = rsrc_base + (sub_offset & 0x7FFFFFFF) as usize;
                    let lang_named = read_u16_le(data, lang_dir + 12).unwrap_or(0) as usize;
                    let lang_id = read_u16_le(data, lang_dir + 14).unwrap_or(0) as usize;
                    let lang_total = (lang_named + lang_id).min(16);

                    for k in 0..lang_total {
                        let lang_entry = lang_dir + 16 + k * 8;
                        if data.len() < lang_entry + 8 {
                            break;
                        }
                        let data_off = read_u32_le(data, lang_entry + 4).unwrap_or(0);
                        if data_off & 0x80000000 == 0 {
                            // Data entry: RVA(4) + Size(4) + CodePage(4) + Reserved(4)
                            let data_entry = rsrc_base + data_off as usize;
                            if let (Some(rva), Some(size)) = (
                                read_u32_le(data, data_entry),
                                read_u32_le(data, data_entry + 4),
                            ) {
                                let file_off =
                                    rva_to_offset(data, opt_offset, rva).unwrap_or(0) as u32;
                                resources.push(PeResource {
                                    type_id,
                                    type_name: resource_type_name(type_id).to_string(),
                                    size,
                                    offset: file_off,
                                });
                                if resources.len() >= MAX_RESOURCES {
                                    return resources;
                                }
                            }
                        }
                    }
                } else {
                    // Direct data entry
                    let data_entry = rsrc_base + sub_offset as usize;
                    if let (Some(rva), Some(size)) = (
                        read_u32_le(data, data_entry),
                        read_u32_le(data, data_entry + 4),
                    ) {
                        let file_off = rva_to_offset(data, opt_offset, rva).unwrap_or(0) as u32;
                        resources.push(PeResource {
                            type_id,
                            type_name: resource_type_name(type_id).to_string(),
                            size,
                            offset: file_off,
                        });
                        if resources.len() >= MAX_RESOURCES {
                            return resources;
                        }
                    }
                }
            }
        }
    }

    resources
}

// ---------------------------------------------------------------------------
// Certificate table (Authenticode)
// ---------------------------------------------------------------------------

/// Parse the PE certificate table (data directory entry #4).
///
/// Unlike other data directories, the certificate table uses a file offset, not an RVA.
fn parse_pe_certificate(data: &[u8], opt_offset: usize, is_64bit: bool) -> Option<PeCertificate> {
    // Certificate table is data directory entry #4
    let dd_offset = if is_64bit {
        opt_offset + 144
    } else {
        opt_offset + 128
    };

    let cert_offset = read_u32_le(data, dd_offset)?;
    let cert_size = read_u32_le(data, dd_offset + 4)?;

    if cert_size == 0 {
        return None;
    }

    Some(PeCertificate {
        offset: cert_offset,
        size: cert_size,
        present: cert_offset > 0 && cert_size > 0 && (cert_offset as usize) < data.len(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_pe_not_pe() {
        assert!(parse_pe(b"\x7fELF").is_none());
        assert!(parse_pe(b"").is_none());
        assert!(parse_pe(b"MZ").is_none()); // too short
    }

    #[test]
    fn parse_pe_minimal_header() {
        // Build a minimal PE: MZ header + PE signature + COFF header + optional header
        let mut data = vec![0u8; 512];

        // DOS header
        data[0] = 0x4d; // M
        data[1] = 0x5a; // Z
        // e_lfanew at 0x3C = 0x80
        data[0x3C] = 0x80;

        // PE signature at 0x80
        data[0x80] = 0x50; // P
        data[0x81] = 0x45; // E
        data[0x82] = 0x00;
        data[0x83] = 0x00;

        // COFF header at 0x84
        data[0x84] = 0x4c; // Machine: i386 (0x014c)
        data[0x85] = 0x01;
        data[0x86] = 0x01; // NumberOfSections: 1
        data[0x87] = 0x00;
        // Timestamp: 0x12345678
        data[0x88] = 0x78;
        data[0x89] = 0x56;
        data[0x8A] = 0x34;
        data[0x8B] = 0x12;
        // SizeOfOptionalHeader at 0x94: 0x70 (112 bytes for PE32)
        data[0x94] = 0x70;
        data[0x95] = 0x00;
        // Characteristics at 0x96: 0x0102 (EXECUTABLE_IMAGE)
        data[0x96] = 0x02;
        data[0x97] = 0x01;

        // Optional header at 0x98
        data[0x98] = 0x0b; // Magic: PE32 (0x010b)
        data[0x99] = 0x01;
        // EntryPoint at 0x98+16 = 0xA8
        data[0xA8] = 0x00;
        data[0xA9] = 0x10;

        // Section header at 0x98 + 0x70 = 0x108
        // Name: ".text\0\0\0"
        data[0x108] = b'.';
        data[0x109] = b't';
        data[0x10A] = b'e';
        data[0x10B] = b'x';
        data[0x10C] = b't';
        // VirtualSize at +8
        data[0x110] = 0x00;
        data[0x111] = 0x10;
        // VirtualAddress at +12
        data[0x114] = 0x00;
        data[0x115] = 0x10;
        // SizeOfRawData at +16
        data[0x118] = 0x00;
        data[0x119] = 0x02;
        // PointerToRawData at +20
        data[0x11C] = 0x00;
        data[0x11D] = 0x02;
        // Characteristics at +36: CODE | EXECUTE | READ
        data[0x12C] = 0x20; // IMAGE_SCN_CNT_CODE
        data[0x12F] = 0x60; // EXECUTE | READ

        let info = parse_pe(&data).unwrap();
        assert_eq!(info.machine, PeMachine::I386);
        assert_eq!(info.num_sections, 1);
        assert_eq!(info.timestamp, 0x12345678);
        assert!(!info.is_dll);
        assert!(!info.is_64bit);
        assert_eq!(info.entry_point, 0x1000);
        assert_eq!(info.sections.len(), 1);
        assert_eq!(info.sections[0].name, ".text");
        assert!(info.sections[0].contains_code());
        assert!(info.sections[0].is_executable());
    }

    #[test]
    fn parse_pe_dll_flag() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        // COFF characteristics: DLL (0x2000)
        data[0x96] = 0x00;
        data[0x97] = 0x20;
        // PE32 magic
        data[0x98] = 0x0b;
        data[0x99] = 0x01;

        let info = parse_pe(&data).unwrap();
        assert!(info.is_dll);
    }

    #[test]
    fn parse_pe_64bit() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x84] = 0x64; // AMD64
        data[0x85] = 0x86;
        // PE32+ magic
        data[0x98] = 0x0b;
        data[0x99] = 0x02;

        let info = parse_pe(&data).unwrap();
        assert!(info.is_64bit);
        assert_eq!(info.machine, PeMachine::Amd64);
    }

    #[test]
    fn pe_machine_display() {
        assert_eq!(PeMachine::I386.to_string(), "i386");
        assert_eq!(PeMachine::Amd64.to_string(), "AMD64");
        assert_eq!(PeMachine::Arm64.to_string(), "ARM64");
        assert_eq!(PeMachine::Unknown(0xFFFF).to_string(), "unknown(0xffff)");
    }

    #[test]
    fn pe_section_flags() {
        let sec = PeSection {
            name: ".data".into(),
            virtual_size: 0x1000,
            virtual_address: 0x2000,
            raw_data_size: 0x200,
            raw_data_offset: 0x400,
            characteristics: 0xC000_0040, // INITIALIZED_DATA | READ | WRITE
        };
        assert!(!sec.is_executable());
        assert!(sec.is_writable());
        assert!(!sec.contains_code());
    }

    #[test]
    fn read_helpers() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05];
        assert_eq!(read_u16_le(&data, 0), Some(0x0201));
        assert_eq!(read_u32_le(&data, 0), Some(0x04030201));
        assert_eq!(read_u16_le(&data, 4), None); // out of bounds
        assert_eq!(read_u32_le(&data, 3), None); // out of bounds
    }

    #[test]
    fn read_ascii_basic() {
        let data = b"hello\0world";
        assert_eq!(read_ascii(data, 0, 11), "hello");
        assert_eq!(read_ascii(data, 6, 5), "world");
    }

    #[test]
    fn parse_pe_truncated_lfanew() {
        // MZ header with e_lfanew pointing past end
        let mut data = vec![0u8; 64];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0xFF; // e_lfanew = 0xFF, past end of 64-byte data
        assert!(parse_pe(&data).is_none());
    }

    #[test]
    fn parse_pe_arm_machine() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x84] = 0xc0; // ARM (0x01c0)
        data[0x85] = 0x01;
        data[0x98] = 0x0b;
        data[0x99] = 0x01;

        let info = parse_pe(&data).unwrap();
        assert_eq!(info.machine, PeMachine::Arm);
    }

    #[test]
    fn parse_pe_bad_pe_signature() {
        let mut data = vec![0u8; 256];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        // Not "PE\0\0"
        data[0x80] = 0x50;
        data[0x81] = 0x50; // PP instead of PE
        assert!(parse_pe(&data).is_none());
    }

    #[test]
    fn read_ascii_past_end() {
        let data = b"hello";
        assert_eq!(read_ascii(data, 100, 5), "");
    }

    #[test]
    fn read_ascii_no_null() {
        let data = b"abcdefgh";
        assert_eq!(read_ascii(data, 0, 8), "abcdefgh");
    }

    #[test]
    fn pe_section_writable_and_executable() {
        let sec = PeSection {
            name: ".mixed".into(),
            virtual_size: 0x1000,
            virtual_address: 0x1000,
            raw_data_size: 0x200,
            raw_data_offset: 0x200,
            characteristics: 0xE000_0020, // CODE | EXECUTE | READ | WRITE
        };
        assert!(sec.is_executable());
        assert!(sec.is_writable());
        assert!(sec.contains_code());
    }

    #[test]
    fn pe_info_serialization_roundtrip() {
        let info = PeInfo {
            machine: PeMachine::Amd64,
            num_sections: 3,
            timestamp: 1234567890,
            is_dll: false,
            is_64bit: true,
            entry_point: 0x1000,
            sections: vec![],
            imports: vec!["kernel32.dll".into()],
            import_functions: vec![],
            exports: vec!["DllMain".into()],
            has_tls_callbacks: false,
            pdb_path: None,
            rich_entries: vec![],
            resources: vec![],
            certificate: None,
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: PeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.machine, PeMachine::Amd64);
        assert_eq!(parsed.imports, vec!["kernel32.dll"]);
    }

    #[test]
    fn imphash_basic() {
        let imports = vec![
            PeImport {
                dll: "kernel32.dll".into(),
                function: "LoadLibraryA".into(),
            },
            PeImport {
                dll: "kernel32.dll".into(),
                function: "GetProcAddress".into(),
            },
        ];
        let hash = compute_imphash(&imports);
        assert_eq!(hash.len(), 32);
        // Same imports = same hash
        assert_eq!(hash, compute_imphash(&imports));
    }

    #[test]
    fn imphash_empty() {
        assert!(compute_imphash(&[]).is_empty());
    }

    #[test]
    fn imphash_case_insensitive() {
        let a = vec![PeImport {
            dll: "KERNEL32.DLL".into(),
            function: "LoadLibraryA".into(),
        }];
        let b = vec![PeImport {
            dll: "kernel32.dll".into(),
            function: "loadlibrarya".into(),
        }];
        assert_eq!(compute_imphash(&a), compute_imphash(&b));
    }

    #[test]
    fn imphash_strips_dll_extension() {
        let a = vec![PeImport {
            dll: "kernel32.dll".into(),
            function: "Func".into(),
        }];
        let b = vec![PeImport {
            dll: "kernel32".into(),
            function: "Func".into(),
        }];
        // Both should produce same hash (extension stripped)
        assert_eq!(compute_imphash(&a), compute_imphash(&b));
    }

    #[test]
    fn parse_pe_excessive_sections_capped() {
        // Crafted PE with num_sections = 65535 — should be capped to MAX_SECTIONS
        let mut data = vec![0u8; 512];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x84] = 0x4c;
        data[0x85] = 0x01;
        // num_sections = 0xFFFF (65535)
        data[0x86] = 0xFF;
        data[0x87] = 0xFF;
        data[0x94] = 0x70;
        data[0x98] = 0x0b;
        data[0x99] = 0x01;

        let info = parse_pe(&data).unwrap();
        assert!(
            info.sections.len() <= super::MAX_SECTIONS,
            "sections should be capped, got {}",
            info.sections.len()
        );
    }

    mod proptest_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #[test]
            fn parse_pe_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                // parse_pe must never panic on any input
                let _ = parse_pe(&data);
            }

            #[test]
            fn parse_pe_with_mz_header(
                rest in proptest::collection::vec(any::<u8>(), 62..2048)
            ) {
                // Valid MZ header prefix + random data — should not panic
                let mut data = vec![0x4d, 0x5a];
                data.extend_from_slice(&rest);
                let _ = parse_pe(&data);
            }

            #[test]
            fn parse_pe_with_pe_sig(
                pe_offset in 0x40u32..0x200,
                rest in proptest::collection::vec(any::<u8>(), 512..2048),
            ) {
                // MZ + plausible e_lfanew + PE sig at that offset
                let mut data = rest;
                if data.len() < (pe_offset as usize) + 100 {
                    data.resize((pe_offset as usize) + 100, 0);
                }
                data[0] = 0x4d;
                data[1] = 0x5a;
                data[0x3C] = pe_offset as u8;
                data[0x3D] = (pe_offset >> 8) as u8;
                let off = pe_offset as usize;
                if off + 4 <= data.len() {
                    data[off] = 0x50;
                    data[off + 1] = 0x45;
                    data[off + 2] = 0x00;
                    data[off + 3] = 0x00;
                }
                let _ = parse_pe(&data);
            }

            #[test]
            fn read_u16_le_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..32),
                offset in 0usize..64
            ) {
                let _ = read_u16_le(&data, offset);
            }

            #[test]
            fn read_u32_le_never_panics(
                data in proptest::collection::vec(any::<u8>(), 0..32),
                offset in 0usize..64
            ) {
                let _ = read_u32_le(&data, offset);
            }
        }
    }

    // ── New feature tests ──────────────────────────────────────────────

    #[test]
    fn parse_pe_pdb_path_absent() {
        // Minimal PE without debug directory — pdb_path should be None
        let mut data = vec![0u8; 512];
        data[0] = 0x4d;
        data[1] = 0x5a;
        data[0x3C] = 0x80;
        data[0x80] = 0x50;
        data[0x81] = 0x45;
        data[0x84] = 0x4c;
        data[0x85] = 0x01;
        data[0x94] = 0x70;
        data[0x98] = 0x0b;
        data[0x99] = 0x01;

        let info = parse_pe(&data).unwrap();
        assert!(info.pdb_path.is_none());
        assert!(!info.has_tls_callbacks);
        assert!(info.rich_entries.is_empty());
    }

    #[test]
    fn rich_entry_serialization() {
        let entry = RichEntry {
            tool_id: 259,
            product_id: 30729,
            count: 42,
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: RichEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.tool_id, 259);
        assert_eq!(parsed.count, 42);
    }
}
