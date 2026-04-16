//! Script language classification and obfuscation detection.
//!
//! Classifies script files by language and detects common obfuscation
//! patterns used in fileless malware attacks.

use crate::analyze::shannon_entropy;
use crate::types::{FindingCategory, FindingSeverity, ScanTarget, ThreatFinding};
use serde::{Deserialize, Serialize};

/// Detected script language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[non_exhaustive]
pub enum ScriptLanguage {
    PowerShell,
    VbScript,
    JavaScript,
    Python,
    Batch,
    Shell,
    Unknown,
}

impl std::fmt::Display for ScriptLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PowerShell => write!(f, "PowerShell"),
            Self::VbScript => write!(f, "VBScript"),
            Self::JavaScript => write!(f, "JavaScript"),
            Self::Python => write!(f, "Python"),
            Self::Batch => write!(f, "Batch"),
            Self::Shell => write!(f, "Shell"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Obfuscation signals detected in a script.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ObfuscationSignals {
    /// Lines with entropy above the high-entropy threshold.
    pub high_entropy_lines: usize,
    /// Total lines analyzed.
    pub total_lines: usize,
    /// Detected obfuscation patterns with descriptions.
    pub patterns: Vec<String>,
    /// Overall obfuscation score (0 = clean, higher = more suspicious).
    pub score: usize,
}

/// Classify the script language from file content.
#[must_use]
pub fn classify_script(data: &[u8]) -> ScriptLanguage {
    // Check shebang first
    if data.len() >= 2 && data[0] == b'#' && data[1] == b'!' {
        let first_line_end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
        let shebang = String::from_utf8_lossy(&data[..first_line_end]);
        if shebang.contains("python") {
            return ScriptLanguage::Python;
        }
        if shebang.contains("bash") || shebang.contains("/sh") || shebang.contains("zsh") {
            return ScriptLanguage::Shell;
        }
        if shebang.contains("node") {
            return ScriptLanguage::JavaScript;
        }
        if shebang.contains("pwsh") || shebang.contains("powershell") {
            return ScriptLanguage::PowerShell;
        }
    }

    // Content-based classification on the first 8KB
    let sample_len = data.len().min(8192);
    let text = String::from_utf8_lossy(&data[..sample_len]);
    let lower = text.to_lowercase();

    // PowerShell indicators
    let ps_score = count_indicators(
        &lower,
        &[
            "$env:",
            "get-",
            "set-",
            "invoke-",
            "new-object",
            "write-host",
            "[system.",
            "[convert]::",
            "param(",
            "-executionpolicy",
            "import-module",
            "add-type",
            "[reflection.",
        ],
    );

    // VBScript indicators
    let vbs_score = count_indicators(
        &lower,
        &[
            "dim ",
            "sub ",
            "function ",
            "wscript.",
            "createobject(",
            "msgbox",
            "on error resume",
            "chr(",
            "cstr(",
            "set ",
        ],
    );

    // JavaScript indicators
    let js_score = count_indicators(
        &lower,
        &[
            "var ",
            "let ",
            "const ",
            "function ",
            "=>",
            "document.",
            "window.",
            "require(",
            "module.exports",
            "console.log",
            "settimeout",
            "addeventlistener",
            "json.parse",
        ],
    );

    // Python indicators
    let py_score = count_indicators(
        &lower,
        &[
            "import ",
            "from ",
            "def ",
            "class ",
            "print(",
            "if __name__",
            "self.",
            "elif ",
            "except:",
            "with open(",
        ],
    );

    // Batch indicators
    let bat_score = count_indicators(
        &lower,
        &[
            "@echo",
            "echo ",
            "set ",
            "goto ",
            "if exist",
            "%~",
            "errorlevel",
            "call ",
            "rem ",
            "pause",
        ],
    );

    // Shell indicators (beyond shebang)
    let sh_score = count_indicators(
        &lower,
        &[
            "#!/", "fi\n", "done\n", "esac", "elif ", "then\n", "export ", "alias ", "source ",
        ],
    );

    let scores = [
        (ScriptLanguage::PowerShell, ps_score),
        (ScriptLanguage::VbScript, vbs_score),
        (ScriptLanguage::JavaScript, js_score),
        (ScriptLanguage::Python, py_score),
        (ScriptLanguage::Batch, bat_score),
        (ScriptLanguage::Shell, sh_score),
    ];

    scores
        .iter()
        .filter(|(_, s)| *s >= 2) // minimum 2 indicators to classify
        .max_by_key(|(_, s)| *s)
        .map(|(lang, _)| *lang)
        .unwrap_or(ScriptLanguage::Unknown)
}

/// Detect obfuscation patterns in script content.
#[must_use]
pub fn detect_obfuscation(data: &[u8], language: ScriptLanguage) -> ObfuscationSignals {
    let mut signals = ObfuscationSignals::default();
    let text = String::from_utf8_lossy(data);
    let lower = text.to_lowercase();

    // Per-line entropy analysis
    let lines: Vec<&str> = text.lines().collect();
    signals.total_lines = lines.len();
    const LINE_ENTROPY_THRESHOLD: f64 = 5.5;

    for line in &lines {
        let trimmed = line.trim();
        if trimmed.len() > 40 {
            let ent = shannon_entropy(trimmed.as_bytes());
            if ent > LINE_ENTROPY_THRESHOLD {
                signals.high_entropy_lines += 1;
            }
        }
    }
    if signals.total_lines > 5 && signals.high_entropy_lines * 3 > signals.total_lines {
        signals
            .patterns
            .push("high per-line entropy (>33% of lines)".into());
        signals.score += 2;
    }

    // Base64 encoded blocks (long strings of base64 chars)
    if memchr::memmem::find(lower.as_bytes(), b"base64").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"frombase64").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"atob(").is_some()
    {
        signals.patterns.push("base64 decode function".into());
        signals.score += 1;
    }

    // Long base64-like strings (60+ chars of A-Za-z0-9+/=)
    for line in &lines {
        let trimmed = line.trim();
        if trimmed.len() >= 60 && is_base64_like(trimmed) {
            signals
                .patterns
                .push("long base64-like string detected".into());
            signals.score += 2;
            break;
        }
    }

    // Language-specific obfuscation patterns
    match language {
        ScriptLanguage::PowerShell => detect_powershell_obfuscation(&lower, &mut signals),
        ScriptLanguage::VbScript => detect_vbscript_obfuscation(&lower, &mut signals),
        ScriptLanguage::JavaScript => detect_javascript_obfuscation(&lower, &mut signals),
        _ => {}
    }

    // Excessive string concatenation (generic)
    let concat_count = text.matches('+').count() + text.matches('&').count();
    if signals.total_lines > 0 && concat_count > signals.total_lines * 3 {
        signals
            .patterns
            .push("excessive string concatenation".into());
        signals.score += 1;
    }

    signals
}

/// Generate findings from script analysis.
#[must_use]
pub fn script_findings(
    language: ScriptLanguage,
    obfuscation: &ObfuscationSignals,
    target: ScanTarget,
) -> Vec<ThreatFinding> {
    if obfuscation.score == 0 {
        return Vec::new();
    }

    let severity = match obfuscation.score {
        1 => FindingSeverity::Low,
        2..=3 => FindingSeverity::Medium,
        _ => FindingSeverity::High,
    };

    let mut f = ThreatFinding::new(
        target,
        FindingCategory::Suspicious,
        severity,
        "script_obfuscation",
        format!(
            "Obfuscated {} script ({} signal{}): {}",
            language,
            obfuscation.score,
            if obfuscation.score == 1 { "" } else { "s" },
            obfuscation.patterns.join("; ")
        ),
    );
    f.metadata
        .insert("script_language".into(), language.to_string());
    f.metadata
        .insert("obfuscation_score".into(), obfuscation.score.to_string());
    f.metadata.insert(
        "high_entropy_lines".into(),
        obfuscation.high_entropy_lines.to_string(),
    );

    vec![f]
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn count_indicators(text: &str, indicators: &[&str]) -> usize {
    indicators
        .iter()
        .filter(|&&ind| memchr::memmem::find(text.as_bytes(), ind.as_bytes()).is_some())
        .count()
}

fn is_base64_like(s: &str) -> bool {
    let b64_chars = s
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'+' || *b == b'/' || *b == b'=')
        .count();
    b64_chars * 100 / s.len() > 90
}

fn detect_powershell_obfuscation(lower: &str, signals: &mut ObfuscationSignals) {
    // [char] casting chains: [char]72+[char]101
    if lower.matches("[char]").count() >= 3 {
        signals
            .patterns
            .push("PowerShell [char] casting chain".into());
        signals.score += 2;
    }
    // Invoke-Expression / IEX
    if memchr::memmem::find(lower.as_bytes(), b"invoke-expression").is_some()
        || (memchr::memmem::find(lower.as_bytes(), b"iex ").is_some()
            || memchr::memmem::find(lower.as_bytes(), b"iex(").is_some())
    {
        signals
            .patterns
            .push("PowerShell Invoke-Expression/IEX".into());
        signals.score += 1;
    }
    // -EncodedCommand
    if memchr::memmem::find(lower.as_bytes(), b"-encodedcommand").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"-enc ").is_some()
    {
        signals.patterns.push("PowerShell -EncodedCommand".into());
        signals.score += 2;
    }
    // String replace obfuscation: -replace
    if lower.matches("-replace").count() >= 3 {
        signals
            .patterns
            .push("PowerShell excessive -replace chains".into());
        signals.score += 1;
    }
    // Hidden window
    if memchr::memmem::find(lower.as_bytes(), b"-windowstyle hidden").is_some() {
        signals.patterns.push("PowerShell hidden window".into());
        signals.score += 1;
    }
}

fn detect_vbscript_obfuscation(lower: &str, signals: &mut ObfuscationSignals) {
    // Chr() concatenation chains
    if lower.matches("chr(").count() >= 5 {
        signals
            .patterns
            .push("VBScript Chr() concatenation chain".into());
        signals.score += 2;
    }
    // Execute/ExecuteGlobal
    if memchr::memmem::find(lower.as_bytes(), b"execute(").is_some()
        || memchr::memmem::find(lower.as_bytes(), b"executeglobal").is_some()
    {
        signals
            .patterns
            .push("VBScript Execute/ExecuteGlobal".into());
        signals.score += 1;
    }
    // WScript.Shell + Run
    if memchr::memmem::find(lower.as_bytes(), b"wscript.shell").is_some() {
        signals.patterns.push("VBScript WScript.Shell".into());
        signals.score += 1;
    }
}

fn detect_javascript_obfuscation(lower: &str, signals: &mut ObfuscationSignals) {
    // eval() usage
    if memchr::memmem::find(lower.as_bytes(), b"eval(").is_some() {
        signals.patterns.push("JavaScript eval()".into());
        signals.score += 1;
    }
    // String.fromCharCode chains
    if lower.matches("fromcharcode").count() >= 2 {
        signals
            .patterns
            .push("JavaScript fromCharCode chain".into());
        signals.score += 2;
    }
    // document.write with encoded content
    if memchr::memmem::find(lower.as_bytes(), b"document.write").is_some()
        && memchr::memmem::find(lower.as_bytes(), b"unescape").is_some()
    {
        signals
            .patterns
            .push("JavaScript document.write+unescape".into());
        signals.score += 2;
    }
    // Hex escape sequences: \x41\x42 chains
    if lower.matches("\\x").count() >= 10 {
        signals
            .patterns
            .push("JavaScript excessive hex escapes".into());
        signals.score += 1;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_powershell() {
        let ps = b"$env:TEMP\nGet-Process | Write-Host\nInvoke-WebRequest http://example.com";
        assert_eq!(classify_script(ps), ScriptLanguage::PowerShell);
    }

    #[test]
    fn classify_python_shebang() {
        let py = b"#!/usr/bin/env python3\nimport os\ndef main():\n    print('hello')";
        assert_eq!(classify_script(py), ScriptLanguage::Python);
    }

    #[test]
    fn classify_javascript() {
        let js = b"const fs = require('fs');\nfunction main() {\n  console.log('hi');\n  let x = JSON.parse(data);\n}";
        assert_eq!(classify_script(js), ScriptLanguage::JavaScript);
    }

    #[test]
    fn classify_batch() {
        let bat = b"@echo off\nset PATH=%PATH%;C:\\tools\nif exist file.txt goto found\npause";
        assert_eq!(classify_script(bat), ScriptLanguage::Batch);
    }

    #[test]
    fn classify_shell_shebang() {
        let sh = b"#!/bin/bash\necho hello\nif [ -f test ]; then\n  echo found\nfi";
        assert_eq!(classify_script(sh), ScriptLanguage::Shell);
    }

    #[test]
    fn classify_vbscript() {
        let vbs = b"Dim objShell\nSet objShell = CreateObject(\"WScript.Shell\")\nSub Main()\n  MsgBox \"hi\"\nEnd Sub";
        assert_eq!(classify_script(vbs), ScriptLanguage::VbScript);
    }

    #[test]
    fn classify_unknown() {
        assert_eq!(
            classify_script(b"just some random text"),
            ScriptLanguage::Unknown
        );
    }

    #[test]
    fn detect_powershell_obfuscation_char_chain() {
        let ps = b"[char]72+[char]101+[char]108+[char]108+[char]111 | iex";
        let lang = ScriptLanguage::PowerShell;
        let signals = detect_obfuscation(ps, lang);
        assert!(signals.score >= 2);
        assert!(signals.patterns.iter().any(|p| p.contains("[char]")));
    }

    #[test]
    fn detect_powershell_encoded_command() {
        let ps = b"powershell -EncodedCommand ZQBjAGgAbwAgACIASABlAGwAbABvACIA";
        let signals = detect_obfuscation(ps, ScriptLanguage::PowerShell);
        assert!(signals.score >= 2);
        assert!(
            signals
                .patterns
                .iter()
                .any(|p| p.contains("EncodedCommand"))
        );
    }

    #[test]
    fn detect_javascript_eval_atob() {
        let js = b"eval(atob('ZG9jdW1lbnQud3JpdGU='));\nconsole.log('done');";
        let signals = detect_obfuscation(js, ScriptLanguage::JavaScript);
        assert!(signals.score >= 2);
    }

    #[test]
    fn detect_vbscript_chr_chain() {
        let vbs = b"x = Chr(72) & Chr(101) & Chr(108) & Chr(108) & Chr(111) & Chr(33)\nExecute(x)";
        let signals = detect_obfuscation(vbs, ScriptLanguage::VbScript);
        assert!(signals.score >= 3);
    }

    #[test]
    fn detect_base64_block() {
        let script = b"data = 'TWFsd2FyZSBwYXlsb2FkIGVuY29kZWQgaW4gYmFzZTY0IGZvcm1hdCBoZXJl'\nresult = base64decode(data)";
        let signals = detect_obfuscation(script, ScriptLanguage::Unknown);
        assert!(signals.score >= 1);
        assert!(signals.patterns.iter().any(|p| p.contains("base64")));
    }

    #[test]
    fn clean_script_no_obfuscation() {
        let clean = b"#!/bin/bash\necho 'Hello World'\nexit 0";
        let signals = detect_obfuscation(clean, ScriptLanguage::Shell);
        assert_eq!(signals.score, 0);
        assert!(signals.patterns.is_empty());
    }

    #[test]
    fn script_findings_severity_scales() {
        let target = ScanTarget::Memory;

        let mut sig = ObfuscationSignals::default();
        assert!(script_findings(ScriptLanguage::Unknown, &sig, target.clone()).is_empty());

        sig.score = 1;
        sig.patterns.push("test".into());
        let f = script_findings(ScriptLanguage::PowerShell, &sig, target.clone());
        assert_eq!(f[0].severity, FindingSeverity::Low);

        sig.score = 3;
        let f = script_findings(ScriptLanguage::PowerShell, &sig, target.clone());
        assert_eq!(f[0].severity, FindingSeverity::Medium);

        sig.score = 5;
        let f = script_findings(ScriptLanguage::PowerShell, &sig, target);
        assert_eq!(f[0].severity, FindingSeverity::High);
    }

    #[test]
    fn script_language_display() {
        assert_eq!(ScriptLanguage::PowerShell.to_string(), "PowerShell");
        assert_eq!(ScriptLanguage::JavaScript.to_string(), "JavaScript");
        assert_eq!(ScriptLanguage::Unknown.to_string(), "Unknown");
    }

    #[test]
    fn is_base64_like_positive() {
        assert!(is_base64_like(
            "TWFsd2FyZSBwYXlsb2FkIGVuY29kZWQgaW4gYmFzZTY0IGZvcm1hdCBoZXJl"
        ));
    }

    #[test]
    fn is_base64_like_negative() {
        assert!(!is_base64_like(
            "Hello, World! This is normal text with spaces."
        ));
    }
}
