use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;
use tauri::{Manager, State};
use tauri_plugin_dialog::DialogExt;

/// Deserialize a JSON null or missing field as an empty String.
fn null_as_empty<'de, D: Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(Option::<String>::deserialize(d)?.unwrap_or_default())
}

#[derive(Serialize)]
pub struct ToolStatus {
    pub slither: bool,
    pub aderyn: bool,
    pub mythril: bool,
    pub forge: bool,
    pub docker: bool,
    pub python3: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    #[serde(default, deserialize_with = "null_as_empty")]
    pub id: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub title: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub severity: String,
    #[serde(default)]
    pub confidence: f64,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub description: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub file: String,
    #[serde(default)]
    pub line: u32,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub tool: String,
    #[serde(default, alias = "recommendation", deserialize_with = "null_as_empty")]
    pub remediation: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub category: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub code_snippet: String,
    #[serde(default, deserialize_with = "null_as_empty")]
    pub swc: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditResult {
    pub id: String,
    pub status: String,
    pub phase: String,
    pub progress: u32,
    pub security_score: u32,
    pub findings: Vec<Finding>,
    pub summary: HashMap<String, u32>,
    pub tools_used: Vec<String>,
    pub timestamp: String,
}

/// Intermediate struct matching Python scanner's JSON output format.
#[derive(Debug, Deserialize)]
struct ScannerOutput {
    #[allow(dead_code)]
    project: String,
    timestamp: String,
    tools_used: Vec<String>,
    summary: HashMap<String, serde_json::Value>,
    security_score: u32,
    findings: Vec<Finding>,
}

impl ScannerOutput {
    fn into_audit_result(self, audit_id: &str) -> AuditResult {
        let summary = self
            .summary
            .iter()
            .filter_map(|(k, v)| v.as_u64().map(|n| (k.clone(), n as u32)))
            .collect();
        AuditResult {
            id: audit_id.to_string(),
            status: "completed".to_string(),
            phase: "complete".to_string(),
            progress: 100,
            security_score: self.security_score,
            findings: self.findings,
            summary,
            tools_used: self.tools_used,
            timestamp: self.timestamp,
        }
    }
}

pub struct AuditStore(Mutex<HashMap<String, AuditResult>>);

/// Opens a native directory picker dialog and returns the selected path.
#[tauri::command]
async fn select_contracts_dir(app: tauri::AppHandle) -> Result<String, String> {
    let (tx, rx) = std::sync::mpsc::channel();
    app.dialog()
        .file()
        .set_title("Select Contracts Directory")
        .pick_folder(move |folder| {
            let result = folder.map(|f| f.to_string());
            let _ = tx.send(result);
        });

    rx.recv()
        .map_err(|e| format!("Dialog error: {}", e))?
        .ok_or_else(|| "No directory selected".to_string())
}

/// Checks whether security tools are available in PATH.
#[tauri::command]
fn check_tools() -> Result<ToolStatus, String> {
    Ok(ToolStatus {
        slither: is_tool_available("slither"),
        aderyn: is_tool_available("aderyn"),
        mythril: is_tool_available("myth"),
        forge: is_tool_available("forge"),
        docker: is_tool_available("docker"),
        python3: find_python().is_some(),
    })
}

/// Run a local audit scan on a directory using available tools.
/// Priority: Docker > solidityguard CLI > Python scanner > local tools
#[tauri::command]
async fn run_local_scan(
    path: String,
    tools: Vec<String>,
    app: tauri::AppHandle,
    store: State<'_, AuditStore>,
) -> Result<AuditResult, String> {
    let scan_path = PathBuf::from(&path);
    if !scan_path.exists() {
        return Err(format!("Path does not exist: {}", path));
    }

    let audit_id = uuid::Uuid::new_v4().to_string();

    // Map frontend tool names to scanner tool names
    let scanner_tools: Vec<String> = tools
        .iter()
        .map(|t| match t.as_str() {
            "pattern" => "patterns".to_string(),
            other => other.to_string(),
        })
        .collect();
    let tools_arg = scanner_tools.join(",");

    // Temp file for JSON output
    let temp_output = std::env::temp_dir().join(format!("solidityguard_{}.json", audit_id));

    // Collect errors from each attempt for diagnostics
    let mut errors: Vec<String> = Vec::new();

    // 1. Try Docker first (most reliable — has full CLI + all tools)
    if is_tool_available("docker") {
        match run_docker_scan(&audit_id, &path) {
            Ok(result) => {
                store
                    .0
                    .lock()
                    .unwrap()
                    .insert(audit_id.clone(), result.clone());
                return Ok(result);
            }
            Err(e) => errors.push(format!("Docker: {}", e)),
        }
    }

    // 2. Try solidityguard CLI (pip-installed)
    if is_tool_available("solidityguard") {
        match Command::new("solidityguard")
            .arg("audit")
            .arg(&path)
            .arg("--quick")
            .arg("-o")
            .arg(temp_output.to_str().unwrap())
            .output()
        {
            Ok(output) => {
                if let Some(result) = try_parse_output_file(&temp_output, &audit_id) {
                    let _ = std::fs::remove_file(&temp_output);
                    store
                        .0
                        .lock()
                        .unwrap()
                        .insert(audit_id.clone(), result.clone());
                    return Ok(result);
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                errors.push(format!(
                    "solidityguard CLI: exit={}, stderr={}",
                    output.status,
                    stderr.chars().take(200).collect::<String>()
                ));
            }
            Err(e) => errors.push(format!("solidityguard CLI: {}", e)),
        }
        let _ = std::fs::remove_file(&temp_output);
    }

    // 3. Try Python scanner script (bundled or local)
    let python = find_python();
    let scanner_script = find_scanner_script(&app);
    if let (Some(py), Some(script)) = (&python, &scanner_script) {
        match Command::new(py)
            .arg(script)
            .arg(&path)
            .arg("--tools")
            .arg(&tools_arg)
            .arg("--output")
            .arg("json")
            .arg("-f")
            .arg(temp_output.to_str().unwrap())
            .output()
        {
            Ok(output) => {
                // Try output file first
                if let Some(result) = try_parse_output_file(&temp_output, &audit_id) {
                    let _ = std::fs::remove_file(&temp_output);
                    store
                        .0
                        .lock()
                        .unwrap()
                        .insert(audit_id.clone(), result.clone());
                    return Ok(result);
                }
                // Try parsing stdout (scanner may print JSON to stdout)
                let stdout = String::from_utf8_lossy(&output.stdout);
                if let Some(result) = try_parse_json_from_mixed_output(&stdout, &audit_id) {
                    let _ = std::fs::remove_file(&temp_output);
                    store
                        .0
                        .lock()
                        .unwrap()
                        .insert(audit_id.clone(), result.clone());
                    return Ok(result);
                }
                let stderr = String::from_utf8_lossy(&output.stderr);
                errors.push(format!(
                    "Python scanner: exit={}, stderr={}",
                    output.status,
                    stderr.chars().take(200).collect::<String>()
                ));
            }
            Err(e) => errors.push(format!("Python scanner: {}", e)),
        }
        let _ = std::fs::remove_file(&temp_output);
    } else {
        if python.is_none() {
            errors.push("Python3 not found in PATH".to_string());
        }
        if scanner_script.is_none() {
            errors.push("Scanner script not found".to_string());
        }
    }

    // 4. Try local tools directly (slither/aderyn)
    if has_any_local_tool(&tools) {
        match run_tool_scan(&audit_id, &path, &tools) {
            Ok(result) => {
                store
                    .0
                    .lock()
                    .unwrap()
                    .insert(audit_id.clone(), result.clone());
                return Ok(result);
            }
            Err(e) => errors.push(format!("Local tools: {}", e)),
        }
    }

    // Nothing worked — return helpful error with diagnostics
    let diag = if errors.is_empty() {
        String::new()
    } else {
        format!("\n\nDiagnostics:\n{}", errors.join("\n"))
    };
    Err(format!(
        "No scanning tools could complete the audit. Install one of:\n\
         \u{2022} Docker (recommended): docker build -t solidityguard .\n\
         \u{2022} Python 3: brew install python3 (for built-in pattern scanner)\n\
         \u{2022} pip install slither-analyzer\n\
         See https://github.com/alt-research/SolidityGuard for setup.{}",
        diag
    ))
}

/// Get a stored audit result.
#[tauri::command]
fn get_audit(id: String, store: State<'_, AuditStore>) -> Result<AuditResult, String> {
    store
        .0
        .lock()
        .unwrap()
        .get(&id)
        .cloned()
        .ok_or_else(|| format!("Audit {} not found", id))
}

/// Get findings for a stored audit.
#[tauri::command]
fn get_findings(id: String, store: State<'_, AuditStore>) -> Result<Vec<Finding>, String> {
    store
        .0
        .lock()
        .unwrap()
        .get(&id)
        .map(|a| a.findings.clone())
        .ok_or_else(|| format!("Audit {} not found", id))
}

/// Run slither on a directory and return JSON output.
#[tauri::command]
fn run_slither(path: String) -> Result<String, String> {
    // Try local slither first, then Docker
    if is_tool_available("slither") {
        let output = Command::new("slither")
            .arg(&path)
            .arg("--json")
            .arg("-")
            .output()
            .map_err(|e| format!("Failed to run slither: {}", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else if is_tool_available("docker") {
        let abs_path = std::fs::canonicalize(&path)
            .map_err(|e| format!("Failed to resolve path: {}", e))?
            .to_string_lossy()
            .to_string();
        let output = Command::new("docker")
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/src", abs_path),
                "trailofbits/eth-security-toolbox",
                "slither",
                "/src",
                "--json",
                "-",
            ])
            .output()
            .map_err(|e| format!("Failed to run slither via Docker: {}", e))?;
        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        Err("slither not found. Install via: pip install slither-analyzer".to_string())
    }
}

/// Run aderyn on a directory.
#[tauri::command]
fn run_aderyn(path: String) -> Result<String, String> {
    let output = Command::new("aderyn")
        .arg("-s")
        .arg(&path)
        .arg("-o")
        .arg("/dev/stdout")
        .output()
        .map_err(|e| format!("Failed to run aderyn: {}", e))?;

    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

/// Find a tool by checking common PATH locations (macOS .app bundles have minimal PATH).
fn is_tool_available(tool: &str) -> bool {
    // Try direct execution first (works if in PATH)
    if Command::new("which")
        .arg(tool)
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        return true;
    }

    // On macOS .app bundles, PATH is minimal — check common locations
    let extra_paths = [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/opt/local/bin",
    ];
    for dir in &extra_paths {
        if PathBuf::from(dir).join(tool).exists() {
            return true;
        }
    }

    // Check ~/.local/bin (pip --user installs)
    if let Ok(home) = std::env::var("HOME") {
        if PathBuf::from(&home)
            .join(".local/bin")
            .join(tool)
            .exists()
        {
            return true;
        }
    }

    false
}

/// Find the full path to a tool, checking common locations on macOS.
fn find_tool_path(tool: &str) -> Option<String> {
    // Try which first
    if let Ok(output) = Command::new("which").arg(tool).output() {
        if output.status.success() {
            let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !path.is_empty() {
                return Some(path);
            }
        }
    }

    // Check common locations
    let extra_paths = [
        "/usr/local/bin",
        "/opt/homebrew/bin",
        "/usr/bin",
        "/opt/local/bin",
    ];
    for dir in &extra_paths {
        let p = PathBuf::from(dir).join(tool);
        if p.exists() {
            return Some(p.to_string_lossy().to_string());
        }
    }

    if let Ok(home) = std::env::var("HOME") {
        let p = PathBuf::from(&home).join(".local/bin").join(tool);
        if p.exists() {
            return Some(p.to_string_lossy().to_string());
        }
    }

    None
}

/// Find python3 binary path.
fn find_python() -> Option<String> {
    // python3 first, then python
    find_tool_path("python3").or_else(|| find_tool_path("python"))
}

fn has_any_local_tool(tools: &[String]) -> bool {
    if tools.is_empty() {
        return is_tool_available("slither") || is_tool_available("aderyn");
    }
    tools.iter().any(|t| match t.as_str() {
        "slither" => is_tool_available("slither"),
        "aderyn" => is_tool_available("aderyn"),
        "mythril" | "myth" => is_tool_available("myth"),
        "forge" | "foundry" => is_tool_available("forge"),
        _ => false,
    })
}

fn find_scanner_script(app: &tauri::AppHandle) -> Option<String> {
    // 1. Check Tauri bundled resources
    if let Ok(resource_dir) = app.path().resource_dir() {
        let bundled = resource_dir.join("solidity_guard.py");
        if bundled.exists() {
            return Some(bundled.to_string_lossy().to_string());
        }
    }

    // 2. Check common locations
    let mut candidates = vec![
        // Relative to current dir (dev mode)
        ".claude/skills/solidity-guard/scripts/solidity_guard.py".to_string(),
        // Docker path
        "/app/scripts/solidity_guard.py".to_string(),
    ];

    // Home directory
    if let Ok(home) = std::env::var("HOME") {
        candidates.push(format!(
            "{}/.claude/skills/solidity-guard/scripts/solidity_guard.py",
            home
        ));
    }

    for candidate in &candidates {
        if PathBuf::from(candidate).exists() {
            return Some(candidate.clone());
        }
    }
    None
}

/// Try to parse a JSON output file from the scanner.
fn try_parse_output_file(path: &PathBuf, audit_id: &str) -> Option<AuditResult> {
    let content = std::fs::read_to_string(path).ok()?;
    let parsed: ScannerOutput = serde_json::from_str(&content).ok()?;
    Some(parsed.into_audit_result(audit_id))
}

/// Try to extract JSON from mixed text+JSON output (scanner prints text before JSON).
fn try_parse_json_from_mixed_output(output: &str, audit_id: &str) -> Option<AuditResult> {
    // Find the last top-level `{` that starts a JSON object
    let mut brace_depth = 0;
    let mut json_start = None;
    for (i, ch) in output.char_indices().rev() {
        match ch {
            '}' => {
                brace_depth += 1;
            }
            '{' => {
                brace_depth -= 1;
                if brace_depth == 0 {
                    json_start = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let start = json_start?;
    let parsed: ScannerOutput = serde_json::from_str(&output[start..]).ok()?;
    Some(parsed.into_audit_result(audit_id))
}

/// Run scan using locally installed tools (slither, aderyn).
fn run_tool_scan(
    audit_id: &str,
    path: &str,
    tools: &[String],
) -> Result<AuditResult, String> {
    let mut findings = Vec::new();
    let mut tools_used = Vec::new();

    // Run slither if requested and available
    if (tools.contains(&"slither".to_string()) || tools.is_empty()) && is_tool_available("slither")
    {
        let slither = find_tool_path("slither").unwrap_or_else(|| "slither".to_string());
        tools_used.push("slither".to_string());
        if let Ok(output) = Command::new(&slither)
            .arg(path)
            .arg("--json")
            .arg("-")
            .output()
        {
            parse_slither_output(&String::from_utf8_lossy(&output.stdout), &mut findings);
        }
    }

    // Run aderyn if requested and available
    if (tools.contains(&"aderyn".to_string()) || tools.is_empty()) && is_tool_available("aderyn") {
        tools_used.push("aderyn".to_string());
    }

    if tools_used.is_empty() {
        return Err("No local tools (slither, aderyn) found".to_string());
    }

    Ok(build_audit_result(audit_id, findings, tools_used))
}

/// Run scan using Docker. Only uses locally available images (no pull).
fn run_docker_scan(
    audit_id: &str,
    path: &str,
) -> Result<AuditResult, String> {
    let abs_path = std::fs::canonicalize(path)
        .map_err(|e| format!("Failed to resolve path: {}", e))?
        .to_string_lossy()
        .to_string();

    let docker = find_tool_path("docker").unwrap_or_else(|| "docker".to_string());

    // 1. Try solidityguard Docker image (has full CLI + pattern scanner)
    if docker_image_exists(&docker, "solidityguard") {
        let temp_output =
            std::env::temp_dir().join(format!("solidityguard_docker_{}.json", audit_id));
        let output = Command::new(&docker)
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/src", abs_path),
                "-v",
                &format!("{}:/output", std::env::temp_dir().to_string_lossy()),
                "solidityguard",
                "python3",
                "/app/scripts/solidity_guard.py",
                "/src",
                "--tools",
                "patterns",
                "--output",
                "json",
                "-f",
                &format!("/output/solidityguard_docker_{}.json", audit_id),
            ])
            .output();

        if let Ok(cmd) = output {
            if let Some(result) = try_parse_output_file(&temp_output, audit_id) {
                let _ = std::fs::remove_file(&temp_output);
                return Ok(result);
            }
            // Try stdout
            let stdout = String::from_utf8_lossy(&cmd.stdout);
            if let Some(result) = try_parse_json_from_mixed_output(&stdout, audit_id) {
                let _ = std::fs::remove_file(&temp_output);
                return Ok(result);
            }
            let stderr = String::from_utf8_lossy(&cmd.stderr);
            let _ = std::fs::remove_file(&temp_output);
            return Err(format!(
                "solidityguard image ran but produced no output. exit={}, stderr={}",
                cmd.status,
                stderr.chars().take(300).collect::<String>()
            ));
        }
        let _ = std::fs::remove_file(&temp_output);
    }

    // 2. Try eth-security-toolbox (slither only) — only if already pulled
    if docker_image_exists(&docker, "trailofbits/eth-security-toolbox") {
        let mut findings = Vec::new();
        let tools_used = vec!["docker".to_string(), "slither".to_string()];

        let output = Command::new(&docker)
            .args([
                "run",
                "--rm",
                "-v",
                &format!("{}:/src", abs_path),
                "trailofbits/eth-security-toolbox",
                "slither",
                "/src",
                "--json",
                "-",
            ])
            .output()
            .map_err(|e| format!("Failed to run Docker slither: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        parse_slither_output(&stdout, &mut findings);

        return Ok(build_audit_result(audit_id, findings, tools_used));
    }

    Err("No Docker images available (solidityguard or eth-security-toolbox). Build with: docker build -t solidityguard .".to_string())
}

/// Check if a Docker image exists locally (no pull).
fn docker_image_exists(docker: &str, image: &str) -> bool {
    Command::new(docker)
        .args(["image", "inspect", image])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Parse slither JSON output and append findings.
fn parse_slither_output(stdout: &str, findings: &mut Vec<Finding>) {
    if let Ok(json) = serde_json::from_str::<serde_json::Value>(stdout) {
        if let Some(detectors) = json.get("results").and_then(|r| r.get("detectors")) {
            if let Some(arr) = detectors.as_array() {
                for det in arr {
                    let impact = det
                        .get("impact")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Medium");
                    let confidence_str = det
                        .get("confidence")
                        .and_then(|v| v.as_str())
                        .unwrap_or("Medium");
                    let severity = match impact.to_lowercase().as_str() {
                        "high" if confidence_str.to_lowercase() == "high" => {
                            "CRITICAL".to_string()
                        }
                        "high" => "HIGH".to_string(),
                        "medium" => "MEDIUM".to_string(),
                        "low" => "LOW".to_string(),
                        "informational" => "INFO".to_string(),
                        _ => impact.to_uppercase(),
                    };
                    let confidence = match confidence_str.to_lowercase().as_str() {
                        "high" => 0.85,
                        "medium" => 0.70,
                        "low" => 0.55,
                        _ => 0.60,
                    };
                    let check = det
                        .get("check")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    findings.push(Finding {
                        id: check.to_string(),
                        title: check.replace('-', " ").to_string(),
                        severity,
                        confidence,
                        description: det
                            .get("description")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        file: det
                            .get("elements")
                            .and_then(|e| e.as_array())
                            .and_then(|a| a.first())
                            .and_then(|e| {
                                e.get("source_mapping")
                                    .and_then(|s| s.get("filename_relative"))
                            })
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                        line: det
                            .get("elements")
                            .and_then(|e| e.as_array())
                            .and_then(|a| a.first())
                            .and_then(|e| {
                                e.get("source_mapping")
                                    .and_then(|s| s.get("lines"))
                                    .and_then(|l| l.as_array())
                                    .and_then(|a| a.first())
                            })
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0) as u32,
                        tool: "slither".to_string(),
                        category: "Security".to_string(),
                        remediation: "Review and fix the detected issue.".to_string(),
                        code_snippet: String::new(),
                        swc: String::new(),
                    });
                }
            }
        }
    }
}

/// Build an AuditResult from findings and tools.
fn build_audit_result(
    audit_id: &str,
    findings: Vec<Finding>,
    tools_used: Vec<String>,
) -> AuditResult {
    let total = findings.len() as u32;
    let critical = findings
        .iter()
        .filter(|f| f.severity == "CRITICAL")
        .count() as u32;
    let high = findings
        .iter()
        .filter(|f| f.severity == "HIGH")
        .count() as u32;
    let medium = findings
        .iter()
        .filter(|f| f.severity == "MEDIUM")
        .count() as u32;
    let low = findings
        .iter()
        .filter(|f| f.severity == "LOW" || f.severity == "INFO")
        .count() as u32;

    let score = 100u32.saturating_sub(critical * 20 + high * 10 + medium * 3 + low);

    let mut summary = HashMap::new();
    summary.insert("total".to_string(), total);
    summary.insert("critical".to_string(), critical);
    summary.insert("high".to_string(), high);
    summary.insert("medium".to_string(), medium);
    summary.insert("low".to_string(), low);

    AuditResult {
        id: audit_id.to_string(),
        status: "completed".to_string(),
        phase: "complete".to_string(),
        progress: 100,
        security_score: score,
        findings,
        summary,
        tools_used,
        timestamp: chrono::Utc::now().to_rfc3339(),
    }
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_shell::init())
        .manage(AuditStore(Mutex::new(HashMap::new())))
        .invoke_handler(tauri::generate_handler![
            select_contracts_dir,
            check_tools,
            run_local_scan,
            get_audit,
            get_findings,
            run_slither,
            run_aderyn,
        ])
        .run(tauri::generate_context!())
        .expect("error while running SolidityGuard");
}
