//! PE (Portable Executable) header parsing.
//!
//! Parses DOS MZ header, PE signature, COFF header, optional header,
//! section table, and import/export directory entries.

use serde::{Deserialize, Serialize};
use std::fmt;

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
    /// Exported function names.
    pub exports: Vec<String>,
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
    pub fn is_executable(&self) -> bool {
        self.characteristics & 0x2000_0000 != 0
    }

    /// Whether this section is writable.
    pub fn is_writable(&self) -> bool {
        self.characteristics & 0x8000_0000 != 0
    }

    /// Whether this section contains code.
    pub fn contains_code(&self) -> bool {
        self.characteristics & 0x0000_0020 != 0
    }
}

/// Read a little-endian u16 from a byte slice at the given offset.
fn read_u16_le(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// Read a little-endian u32 from a byte slice at the given offset.
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

    // Parse section table
    let section_table_offset = opt_offset + optional_header_size;
    let mut sections = Vec::with_capacity(num_sections as usize);

    for i in 0..num_sections as usize {
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

    // Parse import directory (simplified: extract DLL names)
    let imports = parse_pe_imports(data, opt_offset, is_64bit);

    // Parse export directory (simplified: extract function names)
    let exports = parse_pe_exports(data, opt_offset, is_64bit);

    Some(PeInfo {
        machine,
        num_sections,
        timestamp,
        is_dll,
        is_64bit,
        entry_point,
        sections,
        imports,
        exports,
    })
}

/// Parse import directory table to extract DLL names.
fn parse_pe_imports(data: &[u8], opt_offset: usize, is_64bit: bool) -> Vec<String> {
    let mut imports = Vec::new();

    // Import directory is data directory entry #1
    // In PE32: offset 104 from opt header start; PE32+: offset 120
    let dd_offset = if is_64bit {
        opt_offset + 120
    } else {
        opt_offset + 104
    };

    let import_rva = match read_u32_le(data, dd_offset) {
        Some(rva) if rva > 0 => rva,
        _ => return imports,
    };

    // We need to convert RVA to file offset — simplified: scan section table
    let file_offset = match rva_to_offset(data, opt_offset, import_rva) {
        Some(off) => off,
        None => return imports,
    };

    // Each import directory entry is 20 bytes, terminated by an all-zero entry
    let mut idx = file_offset;
    for _ in 0..256 {
        // safety limit
        if data.len() < idx + 20 {
            break;
        }

        let name_rva = match read_u32_le(data, idx + 12) {
            Some(rva) if rva > 0 => rva,
            _ => break,
        };

        if let Some(name_offset) = rva_to_offset(data, opt_offset, name_rva) {
            let name = read_ascii(data, name_offset, 256);
            if !name.is_empty() {
                imports.push(name);
            }
        }

        idx += 20;
    }

    imports
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

    for i in 0..num_names.min(1024) {
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
            exports: vec!["DllMain".into()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: PeInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.machine, PeMachine::Amd64);
        assert_eq!(parsed.imports, vec!["kernel32.dll"]);
    }
}
