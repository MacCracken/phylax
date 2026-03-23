//! phylax-mcp — MCP tool definitions for the Phylax threat detection engine.
//!
//! Exposes 5 tools: phylax_scan, phylax_rules, phylax_status, phylax_quarantine, phylax_report.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Definition of an MCP tool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolDefinition {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Return all Phylax MCP tool definitions.
pub fn list_tools() -> Vec<ToolDefinition> {
    vec![
        ToolDefinition {
            name: "phylax_scan".into(),
            description: "Scan a file, agent, or package for threats using YARA rules, entropy analysis, and magic bytes detection".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Path to file, agent name, or package name to scan"
                    },
                    "target_type": {
                        "type": "string",
                        "enum": ["file", "agent", "package", "memory"],
                        "description": "Type of scan target"
                    },
                    "enable_yara": {
                        "type": "boolean",
                        "description": "Enable YARA rule matching (default: true)"
                    },
                    "enable_entropy": {
                        "type": "boolean",
                        "description": "Enable entropy analysis (default: true)"
                    }
                },
                "required": ["target", "target_type"]
            }),
        },
        ToolDefinition {
            name: "phylax_rules".into(),
            description: "List, search, or inspect loaded YARA rules".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["list", "search", "inspect"],
                        "description": "Action to perform on rules"
                    },
                    "query": {
                        "type": "string",
                        "description": "Search query or rule name to inspect"
                    }
                },
                "required": ["action"]
            }),
        },
        ToolDefinition {
            name: "phylax_status".into(),
            description: "Get the current status of the Phylax threat detection engine".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "boolean",
                        "description": "Include detailed engine statistics"
                    }
                }
            }),
        },
        ToolDefinition {
            name: "phylax_quarantine".into(),
            description: "Quarantine or release a file/agent flagged as a threat".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["quarantine", "release", "list"],
                        "description": "Quarantine action"
                    },
                    "target": {
                        "type": "string",
                        "description": "Path or agent name to quarantine/release"
                    },
                    "reason": {
                        "type": "string",
                        "description": "Reason for quarantine action"
                    }
                },
                "required": ["action"]
            }),
        },
        ToolDefinition {
            name: "phylax_report".into(),
            description: "Generate a threat report for recent scans or a specific target".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "Specific target to report on (omit for full report)"
                    },
                    "format": {
                        "type": "string",
                        "enum": ["json", "text", "markdown"],
                        "description": "Output format (default: json)"
                    },
                    "since": {
                        "type": "string",
                        "description": "ISO 8601 timestamp to filter findings since"
                    }
                }
            }),
        },
    ]
}

/// Number of registered MCP tools.
pub fn tool_count() -> usize {
    list_tools().len()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_tools_returns_five() {
        let tools = list_tools();
        assert_eq!(tools.len(), 5);
    }

    #[test]
    fn tool_names() {
        let tools = list_tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert!(names.contains(&"phylax_scan"));
        assert!(names.contains(&"phylax_rules"));
        assert!(names.contains(&"phylax_status"));
        assert!(names.contains(&"phylax_quarantine"));
        assert!(names.contains(&"phylax_report"));
    }

    #[test]
    fn tool_schemas_are_objects() {
        for tool in list_tools() {
            assert_eq!(
                tool.input_schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "tool {} schema should be an object",
                tool.name
            );
        }
    }

    #[test]
    fn scan_tool_has_required_fields() {
        let tools = list_tools();
        let scan = tools.iter().find(|t| t.name == "phylax_scan").unwrap();
        let required = scan.input_schema.get("required").unwrap();
        let req_arr: Vec<&str> = required
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(req_arr.contains(&"target"));
        assert!(req_arr.contains(&"target_type"));
    }

    #[test]
    fn tool_count_is_five() {
        assert_eq!(tool_count(), 5);
    }

    #[test]
    fn tool_definitions_serialize() {
        let tools = list_tools();
        let json = serde_json::to_string(&tools).unwrap();
        assert!(!json.is_empty());
        // Round-trip
        let parsed: Vec<ToolDefinition> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 5);
    }

    #[test]
    fn tool_descriptions_non_empty() {
        for tool in list_tools() {
            assert!(
                !tool.description.is_empty(),
                "tool {} has empty description",
                tool.name
            );
        }
    }
}
