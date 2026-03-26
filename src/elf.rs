//! ELF (Executable and Linkable Format) parsing.
//!
//! Parses ELF header, section headers, and extracts symbol and dynamic
//! linking information.

use serde::{Deserialize, Serialize};
use std::fmt;

/// Parsed ELF file information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfInfo {
    /// ELF class (32-bit or 64-bit).
    pub class: ElfClass,
    /// Data encoding (little-endian or big-endian).
    pub endian: ElfEndian,
    /// OS/ABI.
    pub os_abi: u8,
    /// Object file type.
    pub file_type: ElfType,
    /// Machine architecture.
    pub machine: ElfMachine,
    /// Entry point virtual address.
    pub entry_point: u64,
    /// Section headers.
    pub sections: Vec<ElfSection>,
    /// Dynamic library dependencies (DT_NEEDED).
    pub needed_libs: Vec<String>,
    /// Symbol names from .dynsym / .symtab.
    pub symbols: Vec<String>,
}

/// ELF class (bitness).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// ELF data encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ElfEndian {
    Little,
    Big,
}

/// ELF object file type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ElfType {
    Relocatable,
    Executable,
    SharedObject,
    Core,
    Unknown(u16),
}

impl fmt::Display for ElfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Relocatable => write!(f, "REL"),
            Self::Executable => write!(f, "EXEC"),
            Self::SharedObject => write!(f, "DYN"),
            Self::Core => write!(f, "CORE"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

/// ELF machine architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ElfMachine {
    X86,
    X86_64,
    Arm,
    Aarch64,
    Mips,
    Riscv,
    Unknown(u16),
}

impl fmt::Display for ElfMachine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(f, "x86"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm => write!(f, "ARM"),
            Self::Aarch64 => write!(f, "AArch64"),
            Self::Mips => write!(f, "MIPS"),
            Self::Riscv => write!(f, "RISC-V"),
            Self::Unknown(v) => write!(f, "unknown({v})"),
        }
    }
}

/// An ELF section header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfSection {
    /// Section name.
    pub name: String,
    /// Section type.
    pub section_type: u32,
    /// Section flags.
    pub flags: u64,
    /// Virtual address.
    pub addr: u64,
    /// File offset.
    pub offset: u64,
    /// Section size.
    pub size: u64,
}

impl ElfSection {
    /// Whether this section is executable (SHF_EXECINSTR).
    #[must_use]
    pub fn is_executable(&self) -> bool {
        self.flags & 0x4 != 0
    }

    /// Whether this section is writable (SHF_WRITE).
    #[must_use]
    pub fn is_writable(&self) -> bool {
        self.flags & 0x1 != 0
    }

    /// Whether this section is allocatable (SHF_ALLOC).
    #[must_use]
    pub fn is_alloc(&self) -> bool {
        self.flags & 0x2 != 0
    }
}

// Section type constants
const SHT_STRTAB: u32 = 3;
const SHT_DYNSYM: u32 = 11;

/// Maximum number of section headers to parse.
const MAX_SECTIONS: usize = 1024;
/// Maximum number of dynamic symbols to extract.
const MAX_SYMBOLS: usize = 4096;
/// Maximum number of DT_NEEDED entries to extract.
const MAX_NEEDED: usize = 1024;

#[inline]
fn read_u16(data: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let b = data.get(offset..offset + 2)?;
    Some(if little_endian {
        u16::from_le_bytes([b[0], b[1]])
    } else {
        u16::from_be_bytes([b[0], b[1]])
    })
}

#[inline]
fn read_u32(data: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let b = data.get(offset..offset + 4)?;
    Some(if little_endian {
        u32::from_le_bytes([b[0], b[1], b[2], b[3]])
    } else {
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    })
}

#[inline]
fn read_u64(data: &[u8], offset: usize, little_endian: bool) -> Option<u64> {
    let b = data.get(offset..offset + 8)?;
    Some(if little_endian {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    } else {
        u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    })
}

/// Read a null-terminated string from a string table.
fn read_strtab_entry(data: &[u8], strtab_offset: usize, name_index: usize) -> String {
    let start = strtab_offset + name_index;
    if start >= data.len() {
        return String::new();
    }
    let end = data[start..]
        .iter()
        .position(|&b| b == 0)
        .map(|p| start + p)
        .unwrap_or(data.len().min(start + 256));
    String::from_utf8_lossy(&data[start..end]).into_owned()
}

/// Try to parse ELF headers from raw file data.
///
/// Returns `None` if the data is not a valid ELF file.
#[must_use]
pub fn parse_elf(data: &[u8]) -> Option<ElfInfo> {
    // ELF magic: 0x7f 'E' 'L' 'F'
    if data.len() < 16 || data[0..4] != [0x7f, 0x45, 0x4c, 0x46] {
        return None;
    }

    let class = match data[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        _ => return None,
    };

    let endian = match data[5] {
        1 => ElfEndian::Little,
        2 => ElfEndian::Big,
        _ => return None,
    };

    let le = endian == ElfEndian::Little;
    let os_abi = data[7];

    let file_type = match read_u16(data, 16, le)? {
        1 => ElfType::Relocatable,
        2 => ElfType::Executable,
        3 => ElfType::SharedObject,
        4 => ElfType::Core,
        v => ElfType::Unknown(v),
    };

    let machine_raw = read_u16(data, 18, le)?;
    let machine = match machine_raw {
        3 => ElfMachine::X86,
        40 => ElfMachine::Arm,
        62 => ElfMachine::X86_64,
        183 => ElfMachine::Aarch64,
        8 => ElfMachine::Mips,
        243 => ElfMachine::Riscv,
        v => ElfMachine::Unknown(v),
    };

    let is_64 = class == ElfClass::Elf64;

    // Parse header fields based on class
    let (entry_point, sh_offset, sh_entsize, sh_num, sh_strndx) = if is_64 {
        if data.len() < 64 {
            return None;
        }
        let entry = read_u64(data, 24, le)?;
        let shoff = read_u64(data, 40, le)? as usize;
        let shentsize = read_u16(data, 58, le)? as usize;
        let shnum = read_u16(data, 60, le)? as usize;
        let shstrndx = read_u16(data, 62, le)? as usize;
        (entry, shoff, shentsize, shnum, shstrndx)
    } else {
        if data.len() < 52 {
            return None;
        }
        let entry = read_u32(data, 24, le)? as u64;
        let shoff = read_u32(data, 32, le)? as usize;
        let shentsize = read_u16(data, 46, le)? as usize;
        let shnum = read_u16(data, 48, le)? as usize;
        let shstrndx = read_u16(data, 50, le)? as usize;
        (entry, shoff, shentsize, shnum, shstrndx)
    };

    if sh_offset == 0 || sh_entsize == 0 || sh_num == 0 {
        return Some(ElfInfo {
            class,
            endian,
            os_abi,
            file_type,
            machine,
            entry_point,
            sections: vec![],
            needed_libs: vec![],
            symbols: vec![],
        });
    }

    // Read section header string table offset
    let shstrtab_offset = if sh_strndx < sh_num {
        let strtab_sh = sh_offset + sh_strndx * sh_entsize;
        if is_64 {
            read_u64(data, strtab_sh + 24, le).unwrap_or(0) as usize
        } else {
            read_u32(data, strtab_sh + 16, le).unwrap_or(0) as usize
        }
    } else {
        0
    };

    // Parse section headers (cap to prevent excessive allocation from crafted headers)
    let capped_sh_num = sh_num.min(MAX_SECTIONS);
    let mut sections = Vec::with_capacity(capped_sh_num);
    let mut dynstr_offset: usize = 0;
    let mut dynsym_sections = Vec::new();

    for i in 0..capped_sh_num {
        let sh = sh_offset + i * sh_entsize;
        if data.len() < sh + sh_entsize {
            break;
        }

        let name_idx = read_u32(data, sh, le).unwrap_or(0) as usize;
        let name = if shstrtab_offset > 0 {
            read_strtab_entry(data, shstrtab_offset, name_idx)
        } else {
            String::new()
        };

        let (sec_type, flags, addr, offset, size) = if is_64 {
            (
                read_u32(data, sh + 4, le).unwrap_or(0),
                read_u64(data, sh + 8, le).unwrap_or(0),
                read_u64(data, sh + 16, le).unwrap_or(0),
                read_u64(data, sh + 24, le).unwrap_or(0),
                read_u64(data, sh + 32, le).unwrap_or(0),
            )
        } else {
            (
                read_u32(data, sh + 4, le).unwrap_or(0),
                read_u32(data, sh + 8, le).unwrap_or(0) as u64,
                read_u32(data, sh + 12, le).unwrap_or(0) as u64,
                read_u32(data, sh + 16, le).unwrap_or(0) as u64,
                read_u32(data, sh + 20, le).unwrap_or(0) as u64,
            )
        };

        if sec_type == SHT_STRTAB && name == ".dynstr" {
            dynstr_offset = offset as usize;
        }
        if sec_type == SHT_DYNSYM {
            dynsym_sections.push((offset as usize, size as usize));
        }

        sections.push(ElfSection {
            name,
            section_type: sec_type,
            flags,
            addr,
            offset,
            size,
        });
    }

    // Extract symbol names from .dynsym using .dynstr
    let mut symbols = Vec::new();
    if dynstr_offset > 0 {
        for &(sym_offset, sym_size) in &dynsym_sections {
            let entry_size = if is_64 { 24 } else { 16 };
            let count = sym_size / entry_size;
            for j in 0..count.min(MAX_SYMBOLS) {
                let ent = sym_offset + j * entry_size;
                let name_idx = read_u32(data, ent, le).unwrap_or(0) as usize;
                if name_idx > 0 {
                    let name = read_strtab_entry(data, dynstr_offset, name_idx);
                    if !name.is_empty() {
                        symbols.push(name);
                    }
                }
            }
        }
    }

    // Extract DT_NEEDED from .dynamic section
    let needed_libs = extract_needed_libs(data, &sections, dynstr_offset, is_64, le);

    Some(ElfInfo {
        class,
        endian,
        os_abi,
        file_type,
        machine,
        entry_point,
        sections,
        needed_libs,
        symbols,
    })
}

/// Extract DT_NEEDED entries from the .dynamic section.
fn extract_needed_libs(
    data: &[u8],
    sections: &[ElfSection],
    dynstr_offset: usize,
    is_64: bool,
    le: bool,
) -> Vec<String> {
    let mut libs = Vec::new();
    if dynstr_offset == 0 {
        return libs;
    }

    // Find .dynamic section (type SHT_DYNAMIC = 6)
    let dynamic = sections.iter().find(|s| s.section_type == 6);
    let dynamic = match dynamic {
        Some(d) => d,
        None => return libs,
    };

    let entry_size = if is_64 { 16 } else { 8 };
    let count = (dynamic.size as usize) / entry_size;
    let base = dynamic.offset as usize;

    for i in 0..count.min(MAX_NEEDED) {
        let ent = base + i * entry_size;
        let tag = if is_64 {
            read_u64(data, ent, le).unwrap_or(0)
        } else {
            read_u32(data, ent, le).unwrap_or(0) as u64
        };

        if tag == 0 {
            break; // DT_NULL
        }

        if tag == 1 {
            // DT_NEEDED
            let val = if is_64 {
                read_u64(data, ent + 8, le).unwrap_or(0) as usize
            } else {
                read_u32(data, ent + 4, le).unwrap_or(0) as usize
            };
            let name = read_strtab_entry(data, dynstr_offset, val);
            if !name.is_empty() {
                libs.push(name);
            }
        }
    }

    libs
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_elf_not_elf() {
        assert!(parse_elf(b"MZ\x90\x00").is_none());
        assert!(parse_elf(b"").is_none());
        assert!(parse_elf(b"\x7fEL").is_none()); // too short
    }

    #[test]
    fn parse_elf_minimal_64() {
        let mut data = vec![0u8; 128];
        // ELF magic
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        // Class: 64-bit
        data[4] = 2;
        // Endian: little
        data[5] = 1;
        // Version
        data[6] = 1;
        // Type: executable (2)
        data[16] = 2;
        data[17] = 0;
        // Machine: x86_64 (62)
        data[18] = 62;
        data[19] = 0;
        // Version
        data[20] = 1;
        // Entry point
        data[24] = 0x00;
        data[25] = 0x04;

        let info = parse_elf(&data).unwrap();
        assert_eq!(info.class, ElfClass::Elf64);
        assert_eq!(info.endian, ElfEndian::Little);
        assert_eq!(info.file_type, ElfType::Executable);
        assert_eq!(info.machine, ElfMachine::X86_64);
        assert_eq!(info.entry_point, 0x0400);
    }

    #[test]
    fn parse_elf_minimal_32() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 1; // 32-bit
        data[5] = 1; // little-endian
        data[6] = 1;
        data[16] = 3; // shared object
        data[18] = 40; // ARM

        let info = parse_elf(&data).unwrap();
        assert_eq!(info.class, ElfClass::Elf32);
        assert_eq!(info.file_type, ElfType::SharedObject);
        assert_eq!(info.machine, ElfMachine::Arm);
    }

    #[test]
    fn elf_type_display() {
        assert_eq!(ElfType::Executable.to_string(), "EXEC");
        assert_eq!(ElfType::SharedObject.to_string(), "DYN");
        assert_eq!(ElfType::Relocatable.to_string(), "REL");
        assert_eq!(ElfType::Core.to_string(), "CORE");
        assert_eq!(ElfType::Unknown(99).to_string(), "unknown(99)");
    }

    #[test]
    fn elf_machine_display() {
        assert_eq!(ElfMachine::X86_64.to_string(), "x86_64");
        assert_eq!(ElfMachine::Aarch64.to_string(), "AArch64");
        assert_eq!(ElfMachine::Riscv.to_string(), "RISC-V");
    }

    #[test]
    fn elf_section_flags() {
        let sec = ElfSection {
            name: ".text".into(),
            section_type: 1,
            flags: 0x6, // ALLOC | EXECINSTR
            addr: 0,
            offset: 0,
            size: 0,
        };
        assert!(sec.is_executable());
        assert!(sec.is_alloc());
        assert!(!sec.is_writable());
    }

    #[test]
    fn elf_info_serialization_roundtrip() {
        let info = ElfInfo {
            class: ElfClass::Elf64,
            endian: ElfEndian::Little,
            os_abi: 0,
            file_type: ElfType::Executable,
            machine: ElfMachine::X86_64,
            entry_point: 0x401000,
            sections: vec![],
            needed_libs: vec!["libc.so.6".into()],
            symbols: vec!["main".into()],
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: ElfInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.machine, ElfMachine::X86_64);
        assert_eq!(parsed.needed_libs, vec!["libc.so.6"]);
    }

    #[test]
    fn parse_elf_big_endian() {
        let mut data = vec![0u8; 128];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 2; // 64-bit
        data[5] = 2; // big-endian
        data[6] = 1;
        // Type: executable (2) in big-endian
        data[16] = 0;
        data[17] = 2;
        // Machine: MIPS (8) in big-endian
        data[18] = 0;
        data[19] = 8;

        let info = parse_elf(&data).unwrap();
        assert_eq!(info.endian, ElfEndian::Big);
        assert_eq!(info.file_type, ElfType::Executable);
        assert_eq!(info.machine, ElfMachine::Mips);
    }

    #[test]
    fn parse_elf_invalid_class() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 99; // invalid class
        data[5] = 1;
        assert!(parse_elf(&data).is_none());
    }

    #[test]
    fn parse_elf_invalid_endian() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 1;
        data[5] = 99; // invalid endian
        assert!(parse_elf(&data).is_none());
    }

    #[test]
    fn parse_elf_relocatable_type() {
        let mut data = vec![0u8; 64];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 1;
        data[5] = 1;
        data[6] = 1;
        data[16] = 1; // REL
        data[18] = 3; // x86

        let info = parse_elf(&data).unwrap();
        assert_eq!(info.file_type, ElfType::Relocatable);
        assert_eq!(info.machine, ElfMachine::X86);
    }

    #[test]
    fn read_strtab_entry_past_end() {
        let data = b"hello\0world";
        assert_eq!(read_strtab_entry(data, 100, 0), "");
    }

    #[test]
    fn read_strtab_entry_basic() {
        let data = b"\0libc.so.6\0libm.so.6\0";
        assert_eq!(read_strtab_entry(data, 0, 1), "libc.so.6");
        assert_eq!(read_strtab_entry(data, 0, 11), "libm.so.6");
    }

    #[test]
    fn elf_section_writable() {
        let sec = ElfSection {
            name: ".data".into(),
            section_type: 1,
            flags: 0x3, // WRITE | ALLOC
            addr: 0,
            offset: 0,
            size: 0,
        };
        assert!(sec.is_writable());
        assert!(sec.is_alloc());
        assert!(!sec.is_executable());
    }

    #[test]
    fn read_helpers() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u16(&data, 0, true), Some(0x0201));
        assert_eq!(read_u16(&data, 0, false), Some(0x0102));
        assert_eq!(read_u32(&data, 0, true), Some(0x04030201));
        assert_eq!(read_u64(&data, 0, true), Some(0x0807060504030201));
    }

    #[test]
    fn parse_elf_excessive_sections_capped() {
        // Crafted ELF with sh_num = 65535 — should be capped to MAX_SECTIONS
        let mut data = vec![0u8; 128];
        data[0] = 0x7f;
        data[1] = 0x45;
        data[2] = 0x4c;
        data[3] = 0x46;
        data[4] = 2; // 64-bit
        data[5] = 1; // little-endian
        data[6] = 1;
        data[16] = 2; // executable
        data[18] = 62; // x86_64
        // sh_offset = 64 (points within data)
        data[40] = 64;
        // sh_entsize = 64
        data[58] = 64;
        // sh_num = 0xFFFF (65535)
        data[60] = 0xFF;
        data[61] = 0xFF;

        let info = parse_elf(&data).unwrap();
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
            fn parse_elf_never_panics(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
                let _ = parse_elf(&data);
            }

            #[test]
            fn parse_elf_with_magic(
                rest in proptest::collection::vec(any::<u8>(), 12..2048)
            ) {
                let mut data = vec![0x7f, 0x45, 0x4c, 0x46];
                data.extend_from_slice(&rest);
                let _ = parse_elf(&data);
            }

            #[test]
            fn parse_elf_32bit_variants(
                endian in 1u8..=2,
                elf_type in 0u16..=5,
                machine in prop::sample::select(vec![3u16, 8, 40, 62, 183, 243, 0xFFFF]),
                rest in proptest::collection::vec(any::<u8>(), 48..1024),
            ) {
                let mut data = rest;
                data.resize(data.len().max(64), 0);
                data[0] = 0x7f;
                data[1] = 0x45;
                data[2] = 0x4c;
                data[3] = 0x46;
                data[4] = 1; // 32-bit
                data[5] = endian;
                data[6] = 1;
                data[16] = elf_type as u8;
                data[17] = (elf_type >> 8) as u8;
                data[18] = machine as u8;
                data[19] = (machine >> 8) as u8;
                let _ = parse_elf(&data);
            }

            #[test]
            fn parse_elf_64bit_variants(
                endian in 1u8..=2,
                elf_type in 0u16..=5,
                rest in proptest::collection::vec(any::<u8>(), 60..1024),
            ) {
                let mut data = rest;
                data.resize(data.len().max(128), 0);
                data[0] = 0x7f;
                data[1] = 0x45;
                data[2] = 0x4c;
                data[3] = 0x46;
                data[4] = 2; // 64-bit
                data[5] = endian;
                data[6] = 1;
                data[16] = elf_type as u8;
                data[17] = (elf_type >> 8) as u8;
                let _ = parse_elf(&data);
            }

            #[test]
            fn read_helpers_never_panic(
                data in proptest::collection::vec(any::<u8>(), 0..32),
                offset in 0usize..64,
                le in any::<bool>(),
            ) {
                let _ = read_u16(&data, offset, le);
                let _ = read_u32(&data, offset, le);
                let _ = read_u64(&data, offset, le);
            }
        }
    }
}
