mod allocator;
mod benchmark;
mod cli;
mod manifest;
mod profiler;
mod report;

use crate::benchmark::macro_bench::run_macro_suite;
use crate::benchmark::micro_bench::run_micro_suite;

use cli::{Args, BenchSuite, FailOn};
use manifest::{GateConfig, GateMetric, load_manifest};
use report::{BenchCase, BenchReport, ReleaseBaselineEntry, ReleaseBaselineIndex};

use clap::Parser;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegressionSeverity {
    Warn,
    Severe,
}

#[derive(Debug, Clone)]
struct RegressionIssue {
    severity: RegressionSeverity,
    metric: &'static str,
    case: String,
    scale: usize,
    kind: String,
    current: f64,
    baseline: f64,
    warn_limit: f64,
    severe_limit: f64,
    unit: &'static str,
}

fn resolve_gate_config(mut gates: GateConfig, args: &Args) -> GateConfig {
    if let Some(cpu_override) = args.cpu_threshold {
        gates.cpu.warn_pct = cpu_override;
        gates.cpu.severe_pct = cpu_override;
    }
    if let Some(mem_override) = args.mem_threshold {
        gates.memory.warn_pct = mem_override;
        gates.memory.severe_pct = mem_override;
        gates.alloc_calls.warn_pct = mem_override;
        gates.alloc_calls.severe_pct = mem_override;
        gates.alloc_bytes.warn_pct = mem_override;
        gates.alloc_bytes.severe_pct = mem_override;
    }
    gates
}

fn classify_regression(
    current: f64,
    baseline: f64,
    gate: &GateMetric,
    zero_limit: f64,
) -> Option<(RegressionSeverity, f64, f64)> {
    let warn = gate.warn_pct.max(0.0);
    let severe = gate.severe_pct.max(warn);

    if baseline > 0.0 {
        // For tiny baselines (for example, allocation calls close to zero),
        // percent-only thresholds are too sensitive to allocator/runtime noise
        // across OS/toolchain environments. Apply a configurable floor so gates
        // remain stable while still catching meaningful growth.
        let effective_baseline = if gate.zero_baseline_limit > 0.0 {
            baseline.max(gate.zero_baseline_limit)
        } else {
            baseline
        };
        let warn_limit = effective_baseline * (1.0 + warn);
        let severe_limit = effective_baseline * (1.0 + severe);
        let delta = current - baseline;
        let min_delta_abs = gate.min_delta_abs.max(0.0);
        if delta < min_delta_abs {
            return None;
        }
        if current > severe_limit {
            return Some((RegressionSeverity::Severe, warn_limit, severe_limit));
        }
        if current > warn_limit {
            return Some((RegressionSeverity::Warn, warn_limit, severe_limit));
        }
        return None;
    }

    let base_limit = if gate.zero_baseline_limit > 0.0 {
        gate.zero_baseline_limit
    } else {
        zero_limit
    };
    let warn_limit = base_limit;
    let severe_limit = base_limit * (1.0 + severe);
    if current > severe_limit {
        return Some((RegressionSeverity::Severe, warn_limit, severe_limit));
    }
    if current > warn_limit {
        return Some((RegressionSeverity::Warn, warn_limit, severe_limit));
    }
    None
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 1.0;
    }
    values.sort_by(|left, right| left.partial_cmp(right).unwrap_or(std::cmp::Ordering::Equal));
    let mid = values.len() / 2;
    if values.len().is_multiple_of(2) {
        (values[mid - 1] + values[mid]) / 2.0
    } else {
        values[mid]
    }
}

fn compare_reports(
    current: &BenchReport,
    baseline: &BenchReport,
    gates: &GateConfig,
) -> Vec<RegressionIssue> {
    let baseline_map: HashMap<(String, String, usize), &BenchCase> = baseline
        .cases
        .iter()
        .map(|case| ((case.kind.clone(), case.name.clone(), case.scale), case))
        .collect();

    let mut cpu_ratios = Vec::new();
    let mut tail_ratios = Vec::new();
    for case in &current.cases {
        let key = (case.kind.clone(), case.name.clone(), case.scale);
        let Some(base) = baseline_map.get(&key) else {
            continue;
        };
        if base.latency_ns_per_op > 0.0 {
            cpu_ratios.push(case.latency_ns_per_op / base.latency_ns_per_op);
        }
        if base.latency_sampled && case.latency_sampled && base.latency_p99_ns > 0.0 {
            tail_ratios.push(case.latency_p99_ns / base.latency_p99_ns);
        }
    }
    // Normalize only for slower environments. Faster runs should not tighten
    // baselines and create artificial regressions when a subset of cases
    // improves significantly.
    let cpu_factor = if cpu_ratios.len() >= 5 {
        median(&mut cpu_ratios).max(1.0)
    } else {
        1.0
    };
    let tail_factor = if tail_ratios.len() >= 5 {
        median(&mut tail_ratios).max(1.0)
    } else {
        1.0
    };

    let mut issues = Vec::new();

    for case in &current.cases {
        let key = (case.kind.clone(), case.name.clone(), case.scale);
        let Some(base) = baseline_map.get(&key) else {
            continue;
        };

        let normalized_cpu_baseline = if base.latency_ns_per_op > 0.0 {
            base.latency_ns_per_op * cpu_factor
        } else {
            base.latency_ns_per_op
        };
        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.latency_ns_per_op,
            normalized_cpu_baseline,
            &gates.cpu,
            0.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "cpu_ns_per_op",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.latency_ns_per_op,
                baseline: normalized_cpu_baseline,
                warn_limit,
                severe_limit,
                unit: "ns/op",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.alloc_calls as f64,
            base.alloc_calls as f64,
            &gates.alloc_calls,
            32.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "alloc_calls",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.alloc_calls as f64,
                baseline: base.alloc_calls as f64,
                warn_limit,
                severe_limit,
                unit: "calls",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.alloc_bytes as f64,
            base.alloc_bytes as f64,
            &gates.alloc_bytes,
            (16 * 1024) as f64,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "alloc_bytes",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.alloc_bytes as f64,
                baseline: base.alloc_bytes as f64,
                warn_limit,
                severe_limit,
                unit: "bytes",
            });
        }

        if let Some((severity, warn_limit, severe_limit)) = classify_regression(
            case.rss_delta_kb as f64,
            base.rss_delta_kb as f64,
            &gates.memory,
            128.0,
        ) {
            issues.push(RegressionIssue {
                severity,
                metric: "rss_delta_kb",
                case: case.name.clone(),
                scale: case.scale,
                kind: case.kind.clone(),
                current: case.rss_delta_kb as f64,
                baseline: base.rss_delta_kb as f64,
                warn_limit,
                severe_limit,
                unit: "KB",
            });
        }

        // Legacy baseline reports may not have tail latency fields populated.
        // Skip tail-p99 regression checks when baseline p99 is unavailable.
        if base.latency_sampled && case.latency_sampled && base.latency_p99_ns > 0.0 {
            let normalized_tail_baseline = base.latency_p99_ns * tail_factor;
            if let Some((severity, warn_limit, severe_limit)) = classify_regression(
                case.latency_p99_ns,
                normalized_tail_baseline,
                &gates.tail_p99,
                0.0,
            ) {
                issues.push(RegressionIssue {
                    severity,
                    metric: "tail_p99_ns",
                    case: case.name.clone(),
                    scale: case.scale,
                    kind: case.kind.clone(),
                    current: case.latency_p99_ns,
                    baseline: normalized_tail_baseline,
                    warn_limit,
                    severe_limit,
                    unit: "ns",
                });
            }
        }
    }

    issues
}

fn print_summary(report: &BenchReport) {
    println!(
        "{:<8} {:<30} {:>7} {:>12} {:>10} {:>12} {:>9}",
        "kind", "case", "scale", "ns/op", "cpu%", "ops/s", "p99(ns)"
    );
    for case in &report.cases {
        println!(
            "{:<8} {:<30} {:>7} {:>12.2} {:>10.2} {:>12.2} {:>9.0}",
            case.kind,
            case.name,
            case.scale,
            case.latency_ns_per_op,
            case.cpu_pct,
            case.throughput_ops_per_sec,
            case.latency_p99_ns
        );
    }
}

fn format_issue(issue: &RegressionIssue) -> String {
    let severity = match issue.severity {
        RegressionSeverity::Warn => "WARN",
        RegressionSeverity::Severe => "SEVERE",
    };
    let delta_pct = if issue.baseline > 0.0 {
        ((issue.current / issue.baseline) - 1.0) * 100.0
    } else {
        0.0
    };

    format!(
        "[{severity}] {} in {}:{} [{}] => {:.2}{} (baseline {:.2}{}, warn>{:.2}{}, severe>{:.2}{}; delta {:.1}%)",
        issue.metric,
        issue.case,
        issue.scale,
        issue.kind,
        issue.current,
        issue.unit,
        issue.baseline,
        issue.unit,
        issue.warn_limit,
        issue.unit,
        issue.severe_limit,
        issue.unit,
        delta_pct
    )
}

fn write_markdown(
    path: &Path,
    report: &BenchReport,
    issues: &[RegressionIssue],
    fail_on: FailOn,
) -> Result<(), String> {
    let mut lines = vec![
        "# Spooky Benchmark Report".to_string(),
        "".to_string(),
        format!("- Report kind: `{}`", report.report_kind),
        format!("- Profile: `{}`", report.profile),
        "".to_string(),
        "| kind | case | scale | ns/op | cpu% | ops/s | p50(ns) | p95(ns) | p99(ns) | alloc_calls | alloc_bytes | rss_delta_kb |".to_string(),
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |".to_string(),
    ];

    for case in &report.cases {
        lines.push(format!(
            "| {} | {} | {} | {:.2} | {:.2} | {:.2} | {:.0} | {:.0} | {:.0} | {} | {} | {} |",
            case.kind,
            case.name,
            case.scale,
            case.latency_ns_per_op,
            case.cpu_pct,
            case.throughput_ops_per_sec,
            case.latency_p50_ns,
            case.latency_p95_ns,
            case.latency_p99_ns,
            case.alloc_calls,
            case.alloc_bytes,
            case.rss_delta_kb
        ));
    }

    lines.push("".to_string());
    if issues.is_empty() {
        lines.push("No regressions detected against baseline.".to_string());
    } else {
        lines.push("## Regression Findings".to_string());
        lines.push(format!("- Fail mode: `{:?}`", fail_on));
        lines.push("".to_string());

        let mut severe = issues
            .iter()
            .filter(|issue| issue.severity == RegressionSeverity::Severe)
            .collect::<Vec<_>>();
        let mut warn = issues
            .iter()
            .filter(|issue| issue.severity == RegressionSeverity::Warn)
            .collect::<Vec<_>>();

        severe.sort_by_key(|issue| (&issue.kind, &issue.case, issue.scale, issue.metric));
        warn.sort_by_key(|issue| (&issue.kind, &issue.case, issue.scale, issue.metric));

        if !severe.is_empty() {
            lines.push("### Severe".to_string());
            for issue in severe {
                lines.push(format!("- {}", format_issue(issue)));
            }
            lines.push("".to_string());
        }

        if !warn.is_empty() {
            lines.push("### Warn".to_string());
            for issue in warn {
                lines.push(format!("- {}", format_issue(issue)));
            }
        }
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create markdown dir '{}': {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, lines.join("\n"))
        .map_err(|err| format!("failed to write markdown '{}': {err}", path.display()))
}

fn load_report(path: &Path) -> Result<BenchReport, String> {
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read baseline '{}': {err}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|err| format!("failed to parse baseline '{}': {err}", path.display()))
}

fn load_release_index(path: &Path) -> Result<ReleaseBaselineIndex, String> {
    if !path.exists() {
        return Ok(ReleaseBaselineIndex::default());
    }
    let text = fs::read_to_string(path)
        .map_err(|err| format!("failed to read baseline index '{}': {err}", path.display()))?;
    serde_json::from_str(&text)
        .map_err(|err| format!("failed to parse baseline index '{}': {err}", path.display()))
}

fn write_release_index(path: &Path, index: &ReleaseBaselineIndex) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "failed to create baseline index dir '{}': {err}",
                parent.display()
            )
        })?;
    }
    let text = serde_json::to_string_pretty(index)
        .map_err(|err| format!("failed to serialize baseline index: {err}"))?;
    fs::write(path, text)
        .map_err(|err| format!("failed to write baseline index '{}': {err}", path.display()))
}

fn write_report(path: &Path, report: &BenchReport) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create output dir '{}': {err}", parent.display()))?;
    }
    let json =
        serde_json::to_string_pretty(report).map_err(|err| format!("serialize report: {err}"))?;
    fs::write(path, json)
        .map_err(|err| format!("failed to write report '{}': {err}", path.display()))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn suite_label(suite: BenchSuite) -> &'static str {
    match suite {
        BenchSuite::Micro => "micro",
        BenchSuite::Macro => "macro",
        BenchSuite::All => "all",
    }
}

fn resolve_baseline_paths(
    args: &Args,
    release_index: &ReleaseBaselineIndex,
) -> Result<Vec<PathBuf>, String> {
    if let Some(path) = &args.baseline {
        return Ok(vec![path.clone()]);
    }

    let release = args
        .baseline_release
        .clone()
        .or_else(|| {
            (!release_index.current_release.is_empty()).then_some(release_index.current_release.clone())
        })
        .ok_or_else(|| {
            "baseline not specified; pass --baseline or configure --baseline-release / current_release in baseline index".to_string()
        })?;

    let entry = release_index
        .releases
        .get(&release)
        .ok_or_else(|| format!("release '{release}' missing from baseline index"))?;

    let paths = match args.suite {
        BenchSuite::Micro => vec![PathBuf::from(&entry.micro)],
        BenchSuite::Macro => vec![PathBuf::from(&entry.macro_report)],
        BenchSuite::All => vec![
            PathBuf::from(&entry.micro),
            PathBuf::from(&entry.macro_report),
        ],
    };

    Ok(paths)
}

fn merge_reports(reports: Vec<BenchReport>) -> BenchReport {
    let mut merged = BenchReport {
        suite: "spooky-performance-baseline".to_string(),
        report_kind: "merged".to_string(),
        profile: "baseline".to_string(),
        generated_unix_secs: unix_now(),
        ..BenchReport::default()
    };

    for report in reports {
        merged.cases.extend(report.cases);
    }

    merged.cases.sort_by(|left, right| {
        (&left.kind, &left.name, left.scale).cmp(&(&right.kind, &right.name, right.scale))
    });
    merged
}

fn run_promotion(args: &Args) -> Result<(), String> {
    let release = args
        .promote_release
        .as_ref()
        .ok_or_else(|| "internal error: promote_release missing".to_string())?;

    let mut index = load_release_index(&args.baseline_index)?;

    let release_dir = PathBuf::from("bench").join("baselines").join(release);
    fs::create_dir_all(&release_dir).map_err(|err| {
        format!(
            "failed to create release baseline directory '{}': {err}",
            release_dir.display()
        )
    })?;

    if !args.promote_micro_report.exists() {
        return Err(format!(
            "micro report '{}' does not exist",
            args.promote_micro_report.display()
        ));
    }
    if !args.promote_macro_report.exists() {
        return Err(format!(
            "macro report '{}' does not exist",
            args.promote_macro_report.display()
        ));
    }

    let micro_dest = release_dir.join("micro.json");
    let macro_dest = release_dir.join("macro.json");

    fs::copy(&args.promote_micro_report, &micro_dest).map_err(|err| {
        format!(
            "failed to copy micro report '{}' -> '{}': {err}",
            args.promote_micro_report.display(),
            micro_dest.display()
        )
    })?;
    fs::copy(&args.promote_macro_report, &macro_dest).map_err(|err| {
        format!(
            "failed to copy macro report '{}' -> '{}': {err}",
            args.promote_macro_report.display(),
            macro_dest.display()
        )
    })?;

    let entry = ReleaseBaselineEntry {
        micro: micro_dest.to_string_lossy().to_string(),
        macro_report: macro_dest.to_string_lossy().to_string(),
    };
    index.releases.insert(release.clone(), entry);
    if args.set_current_release {
        index.current_release = release.clone();
    }

    write_release_index(&args.baseline_index, &index)?;

    println!(
        "Promoted release baseline '{}' (micro='{}', macro='{}')",
        release,
        micro_dest.display(),
        macro_dest.display()
    );

    Ok(())
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    if args.promote_release.is_some() {
        return run_promotion(&args);
    }

    let manifest = load_manifest(&args.manifest)?;
    let profile = manifest
        .profiles
        .get(&args.profile)
        .ok_or_else(|| format!("profile '{}' missing in manifest", args.profile))?;

    let mut cases = Vec::new();
    match args.suite {
        BenchSuite::Micro => {
            cases.extend(run_micro_suite(profile, &manifest.micro)?);
        }
        BenchSuite::Macro => {
            cases.extend(run_macro_suite(profile, &manifest.macro_suite)?);
        }
        BenchSuite::All => {
            cases.extend(run_micro_suite(profile, &manifest.micro)?);
            cases.extend(run_macro_suite(profile, &manifest.macro_suite)?);
        }
    }

    cases.sort_by(|left, right| {
        (&left.kind, &left.name, left.scale).cmp(&(&right.kind, &right.name, right.scale))
    });

    let report = BenchReport {
        suite: "spooky-performance-regression".to_string(),
        report_kind: suite_label(args.suite).to_string(),
        profile: args.profile.clone(),
        generated_unix_secs: unix_now(),
        cpu_threshold: args.cpu_threshold.unwrap_or(manifest.gates.cpu.warn_pct),
        mem_threshold: args.mem_threshold.unwrap_or(manifest.gates.memory.warn_pct),
        cases,
    };

    print_summary(&report);
    write_report(&args.output, &report)?;

    let mut issues = Vec::new();
    if args.check_baseline {
        let release_index = load_release_index(&args.baseline_index)?;
        let baseline_paths = resolve_baseline_paths(&args, &release_index)?;
        let mut baseline_reports = Vec::with_capacity(baseline_paths.len());
        for path in &baseline_paths {
            baseline_reports.push(load_report(path)?);
        }
        let baseline = merge_reports(baseline_reports);

        let gates = resolve_gate_config(manifest.gates.clone(), &args);
        issues = compare_reports(&report, &baseline, &gates);
    }

    if let Some(markdown) = &args.markdown_out {
        write_markdown(markdown, &report, &issues, args.fail_on)?;
    }

    if !issues.is_empty() {
        let severe_count = issues
            .iter()
            .filter(|issue| issue.severity == RegressionSeverity::Severe)
            .count();
        let warn_count = issues.len().saturating_sub(severe_count);

        for issue in &issues {
            eprintln!("{}", format_issue(issue));
        }

        let fail = match args.fail_on {
            FailOn::Severe => severe_count > 0,
            FailOn::Any => !issues.is_empty(),
        };

        if fail {
            return Err(format!(
                "benchmark regression gate failed (severe={severe_count}, warn={warn_count}, mode={:?})",
                args.fail_on
            ));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{GateMetric, RegressionSeverity, classify_regression};

    fn gate(
        warn_pct: f64,
        severe_pct: f64,
        zero_baseline_limit: f64,
        min_delta_abs: f64,
    ) -> GateMetric {
        GateMetric {
            warn_pct,
            severe_pct,
            zero_baseline_limit,
            min_delta_abs,
        }
    }

    #[test]
    fn min_delta_abs_suppresses_small_absolute_memory_drift() {
        let memory_gate = gate(0.20, 0.40, 128.0, 256.0);
        let regression = classify_regression(320.0, 200.0, &memory_gate, 128.0);
        assert!(regression.is_none());
    }

    #[test]
    fn min_delta_abs_still_allows_large_absolute_memory_regressions() {
        let memory_gate = gate(0.20, 0.40, 128.0, 256.0);
        let regression = classify_regression(520.0, 200.0, &memory_gate, 128.0);
        assert!(matches!(
            regression,
            Some((RegressionSeverity::Severe, _, _))
        ));
    }
}
