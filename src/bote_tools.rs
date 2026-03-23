//! Bote MCP tool registration for Phylax.
//!
//! Registers phylax's scan, rules, status, quarantine, and report tools
//! with a bote `ToolRegistry` and `Dispatcher`.
//!
//! Requires the `bote` feature flag.

use bote::dispatch::ToolHandler;
use bote::{ToolDef, ToolRegistry, ToolSchema};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;

/// Build a `ToolRegistry` containing all Phylax MCP tool definitions.
pub fn phylax_registry() -> ToolRegistry {
    let mut registry = ToolRegistry::new();

    registry.register(scan_tool());
    registry.register(rules_tool());
    registry.register(status_tool());
    registry.register(quarantine_tool());
    registry.register(report_tool());

    registry
}

/// Build the phylax_scan tool handler.
pub fn scan_handler() -> ToolHandler {
    Arc::new(|args: Value| {
        let target = args
            .get("target")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // Canonicalize to prevent path traversal
        let path = match std::fs::canonicalize(target) {
            Ok(p) => p,
            Err(e) => return json!({"error": format!("invalid path: {e}")}),
        };

        let data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(e) => return json!({"error": e.to_string()}),
        };
        let analysis = crate::analyze::analyze(&data);
        json!({
            "file_type": analysis.file_type.to_string(),
            "entropy": analysis.entropy,
            "sha256": analysis.sha256,
            "size": analysis.size,
            "suspicious_entropy": crate::analyze::is_suspicious_entropy(analysis.entropy),
        })
    })
}

/// Build the phylax_status tool handler.
pub fn status_handler() -> ToolHandler {
    Arc::new(|_args: Value| {
        json!({
            "status": "ready",
            "version": crate::types::VERSION,
            "analyzers": ["entropy", "magic_bytes", "yara", "polyglot", "pe", "elf", "strings"],
        })
    })
}

// ---------------------------------------------------------------------------
// Tool definitions
// ---------------------------------------------------------------------------

fn scan_tool() -> ToolDef {
    ToolDef {
        name: "phylax_scan".into(),
        description:
            "Scan a file for threats using YARA rules, entropy analysis, and magic bytes detection"
                .into(),
        input_schema: ToolSchema {
            schema_type: "object".into(),
            properties: HashMap::from([
                (
                    "target".into(),
                    json!({"type": "string", "description": "Path to file to scan"}),
                ),
                (
                    "target_type".into(),
                    json!({"type": "string", "enum": ["file", "agent", "package", "memory"]}),
                ),
                (
                    "enable_yara".into(),
                    json!({"type": "boolean", "description": "Enable YARA rule matching"}),
                ),
                (
                    "enable_entropy".into(),
                    json!({"type": "boolean", "description": "Enable entropy analysis"}),
                ),
            ]),
            required: vec!["target".into(), "target_type".into()],
        },
    }
}

fn rules_tool() -> ToolDef {
    ToolDef {
        name: "phylax_rules".into(),
        description: "List, search, or inspect loaded YARA rules".into(),
        input_schema: ToolSchema {
            schema_type: "object".into(),
            properties: HashMap::from([
                (
                    "action".into(),
                    json!({"type": "string", "enum": ["list", "search", "inspect"]}),
                ),
                (
                    "query".into(),
                    json!({"type": "string", "description": "Search query or rule name"}),
                ),
            ]),
            required: vec!["action".into()],
        },
    }
}

fn status_tool() -> ToolDef {
    ToolDef {
        name: "phylax_status".into(),
        description: "Get the current status of the Phylax threat detection engine".into(),
        input_schema: ToolSchema {
            schema_type: "object".into(),
            properties: HashMap::from([(
                "verbose".into(),
                json!({"type": "boolean", "description": "Include detailed statistics"}),
            )]),
            required: vec![],
        },
    }
}

fn quarantine_tool() -> ToolDef {
    ToolDef {
        name: "phylax_quarantine".into(),
        description: "Quarantine or release a file flagged as a threat".into(),
        input_schema: ToolSchema {
            schema_type: "object".into(),
            properties: HashMap::from([
                (
                    "action".into(),
                    json!({"type": "string", "enum": ["quarantine", "release", "list"]}),
                ),
                (
                    "target".into(),
                    json!({"type": "string", "description": "Path or quarantine ID"}),
                ),
                (
                    "reason".into(),
                    json!({"type": "string", "description": "Reason for action"}),
                ),
            ]),
            required: vec!["action".into()],
        },
    }
}

fn report_tool() -> ToolDef {
    ToolDef {
        name: "phylax_report".into(),
        description: "Generate a threat report for recent scans".into(),
        input_schema: ToolSchema {
            schema_type: "object".into(),
            properties: HashMap::from([
                (
                    "target".into(),
                    json!({"type": "string", "description": "Specific target to report on"}),
                ),
                (
                    "format".into(),
                    json!({"type": "string", "enum": ["json", "markdown"]}),
                ),
            ]),
            required: vec![],
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_has_five_tools() {
        let registry = phylax_registry();
        assert_eq!(registry.list().len(), 5);
    }

    #[test]
    fn registry_tool_names() {
        let registry = phylax_registry();
        let names: Vec<&str> = registry.list().iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"phylax_scan"));
        assert!(names.contains(&"phylax_rules"));
        assert!(names.contains(&"phylax_status"));
        assert!(names.contains(&"phylax_quarantine"));
        assert!(names.contains(&"phylax_report"));
    }

    #[test]
    fn scan_tool_schema() {
        let registry = phylax_registry();
        let tool = registry.get("phylax_scan").unwrap();
        assert!(tool.input_schema.required.contains(&"target".into()));
        assert!(tool.input_schema.required.contains(&"target_type".into()));
    }

    #[test]
    fn status_handler_returns_ready() {
        let handler = status_handler();
        let result = handler(json!({}));
        assert_eq!(result.get("status").unwrap().as_str().unwrap(), "ready");
        assert!(result.get("version").is_some());
    }
}
