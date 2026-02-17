use colored::*;
use std::time::Duration;

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Constants
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
const W: usize = 78; // inner width

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Box-drawing helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn top(w: usize) -> String    { format!("  ╔{}╗", "═".repeat(w)) }
fn mid(w: usize) -> String    { format!("  ╠{}╣", "═".repeat(w)) }
fn bot(w: usize) -> String    { format!("  ╚{}╝", "═".repeat(w)) }
fn thin_top(w: usize) -> String  { format!("  ┌{}┐", "─".repeat(w)) }
fn thin_mid(w: usize) -> String  { format!("  ├{}┤", "─".repeat(w)) }
fn thin_bot(w: usize) -> String  { format!("  └{}┘", "─".repeat(w)) }
fn row(content: &str, w: usize) -> String {
    // Pad content to width, accounting for ANSI escape codes
    let visible_len = strip_ansi(content).chars().count();
    let pad = if visible_len < w { w - visible_len } else { 0 };
    format!("  ║ {}{} ║", content, " ".repeat(pad))
}
fn thin_row(content: &str, w: usize) -> String {
    let visible_len = strip_ansi(content).chars().count();
    let pad = if visible_len < w { w - visible_len } else { 0 };
    format!("  │ {}{} │", content, " ".repeat(pad))
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::new();
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' { in_escape = true; continue; }
        if in_escape { if c == 'm' { in_escape = false; } continue; }
        out.push(c);
    }
    out
}

fn center(text: &str, w: usize) -> String {
    let vl = strip_ansi(text).chars().count();
    if vl >= w { return text.to_string(); }
    let left = (w - vl) / 2;
    let right = w - vl - left;
    format!("{}{}{}", " ".repeat(left), text, " ".repeat(right))
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Gradient text (cyan → blue → magenta)
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn gradient_line(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len().max(1);
    let mut out = String::new();
    for (i, c) in chars.iter().enumerate() {
        let t = i as f64 / len as f64;
        let (r, g, b) = if t < 0.5 {
            let s = t * 2.0;
            ((80.0 + s * 80.0) as u8, (200.0 - s * 100.0) as u8, (255.0 - s * 55.0) as u8)
        } else {
            let s = (t - 0.5) * 2.0;
            ((160.0 + s * 95.0) as u8, (100.0 - s * 50.0) as u8, (200.0 + s * 55.0) as u8)
        };
        out.push_str(&format!("\x1b[38;2;{};{};{}m{}\x1b[0m", r, g, b, c));
    }
    out
}



// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Severity helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
fn sev_badge(severity: u8) -> String {
    match severity {
        5 => " CRITICAL ".on_red().white().bold().to_string(),
        4 => "   HIGH   ".on_truecolor(255,140,0).white().bold().to_string(),
        3 => "  MEDIUM  ".on_truecolor(59,130,246).white().bold().to_string(),
        2 => "   LOW    ".on_truecolor(100,116,139).white().to_string(),
        _ => "   INFO   ".on_truecolor(71,85,105).white().to_string(),
    }
}



fn conf_bar(confidence: u8) -> String {
    let filled = (confidence as usize * 10) / 100;
    let empty = 10 - filled;
    let color = if confidence >= 80 { (34,197,94) }
                else if confidence >= 50 { (234,179,8) }
                else { (239,68,68) };
    format!("{}{} {}%",
        "█".repeat(filled).truecolor(color.0, color.1, color.2),
        "░".repeat(empty).truecolor(60,60,60),
        confidence)
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Banner
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn print_banner() {
    let iw = W - 2;
    let logo_lines = [
        r"██████╗ ██████╗  ██╗ ██╗ ███╗   ██╗",
        r"██╔═══██╗██╔══██╗███║ ██║ ████╗  ██║",
        r"╚██████╔╝██████╔╝╚██║ ██║ ██╔██╗ ██║",
        r" ██╔═══╝ ██╔══██╗ ██║ ██║ ██║╚██╗██║",
        r" ███████╗██║  ██║ ██║ ██║ ██║ ╚████║",
        r" ╚══════╝╚═╝  ╚═╝ ╚═╝ ╚═╝ ╚═╝  ╚═══╝",
    ];

    eprintln!();
    eprintln!("{}", top(W).truecolor(80,200,255));
    eprintln!("{}", row("", iw).truecolor(80,200,255));
    for line in &logo_lines {
        eprintln!("{}", row(&center(&gradient_line(line), iw), iw).truecolor(80,200,255));
    }
    eprintln!("{}", row("", iw).truecolor(80,200,255));
    let subtitle = gradient_line("Enterprise-Grade Solana Security Auditor");
    eprintln!("{}", row(&center(&subtitle, iw), iw).truecolor(80,200,255));
    let ver = format!("{}", "v2.0.0".truecolor(120,120,120));
    eprintln!("{}", row(&center(&ver, iw), iw).truecolor(80,200,255));
    eprintln!("{}", row("", iw).truecolor(80,200,255));
    eprintln!("{}", mid(W).truecolor(80,200,255));

    // Engine badges row
    let engines = [
        ("PATTERN", (239,68,68)),
        ("DEEP-AST", (168,85,247)),
        ("TAINT", (234,179,8)),
        ("CFG", (6,182,212)),
        ("INTERVAL", (34,197,94)),
        ("ALIAS", (59,130,246)),
    ];
    let mut badge_line = String::new();
    for (name, (r,g,b)) in &engines {
        badge_line.push_str(&format!(" {} ", format!(" {} ", name).on_truecolor(*r,*g,*b).white().bold()));
        badge_line.push(' ');
    }
    eprintln!("{}", row(&center(&badge_line, iw), iw).truecolor(80,200,255));
    eprintln!("{}", row("", iw).truecolor(80,200,255));
    eprintln!("{}", bot(W).truecolor(80,200,255));
    eprintln!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Pipeline visualization
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub struct EngineResult {
    pub name: &'static str,
    pub desc: &'static str,
    pub findings: usize,
    pub color: (u8, u8, u8),
}

pub fn print_pipeline(target: &str, engines: &[EngineResult], elapsed: Duration) {
    let iw = W - 2;
    eprintln!("{}", thin_top(W).truecolor(100,116,139));
    let header = format!(
        "{}  {}  {}",
        "⚡".truecolor(234,179,8),
        "ANALYSIS PIPELINE".bright_white().bold(),
        format!("[{:.2}s]", elapsed.as_secs_f64()).truecolor(100,116,139),
    );
    eprintln!("{}", thin_row(&header, iw).truecolor(100,116,139));
    let tgt = format!("{}  {}", "Target:".truecolor(100,116,139), target.bright_white());
    eprintln!("{}", thin_row(&tgt, iw).truecolor(100,116,139));
    eprintln!("{}", thin_mid(W).truecolor(100,116,139));

    for (i, e) in engines.iter().enumerate() {
        let status = if e.findings > 0 {
            format!("{} {}", e.findings.to_string().red().bold(), "found".truecolor(100,116,139))
        } else {
            format!("{}", "✓ clean".truecolor(34,197,94))
        };
        let connector = if i < engines.len() - 1 { "│" } else { " " };
        let num = format!("{}", format!("E{}", i+1).truecolor(e.color.0, e.color.1, e.color.2).bold());
        let line = format!(
            "  {} {:<22} {} {:>14}",
            num,
            e.name.truecolor(e.color.0, e.color.1, e.color.2),
            format!("│ {}", e.desc).truecolor(80,80,80),
            status,
        );
        eprintln!("{}", thin_row(&line, iw).truecolor(100,116,139));
        if i < engines.len() - 1 {
            let pipe = format!("  {}   {}", connector.truecolor(60,60,60), "↓".truecolor(60,60,60));
            eprintln!("{}", thin_row(&pipe, iw).truecolor(100,116,139));
        }
    }

    eprintln!("{}", thin_bot(W).truecolor(100,116,139));
    eprintln!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Summary dashboard
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn print_summary(critical: usize, high: usize, medium: usize, low: usize, total: usize, elapsed: Duration) {
    let iw = W - 2;
    eprintln!("{}", top(W).truecolor(80,200,255));
    let title = format!("{}", "SCAN RESULTS".bright_white().bold());
    eprintln!("{}", row(&center(&title, iw), iw).truecolor(80,200,255));
    eprintln!("{}", mid(W).truecolor(80,200,255));

    // Severity counters in a row
    let counters = format!(
        "  {}  {}    {}  {}    {}  {}    {}  {}",
        "●".red().bold(), format!("{} Critical", critical).red().bold(),
        "●".truecolor(255,140,0), format!("{} High", high).truecolor(255,140,0),
        "●".truecolor(59,130,246), format!("{} Medium", medium).truecolor(59,130,246),
        "●".truecolor(100,116,139), format!("{} Low", low).truecolor(100,116,139),
    );
    eprintln!("{}", row(&counters, iw).truecolor(80,200,255));
    eprintln!("{}", row("", iw).truecolor(80,200,255));

    // Distribution bar
    let bar_w: usize = 50;
    let t = total.max(1);
    let c_w = (critical * bar_w) / t;
    let h_w = (high * bar_w) / t;
    let m_w = (medium * bar_w) / t;
    let l_w = bar_w.saturating_sub(c_w + h_w + m_w);
    let bar = format!(
        "  {} {}{}{}{}",
        "Distribution".truecolor(100,116,139),
        "█".repeat(c_w).red(),
        "█".repeat(h_w).truecolor(255,140,0),
        "█".repeat(m_w).truecolor(59,130,246),
        "░".repeat(l_w).truecolor(60,60,60),
    );
    eprintln!("{}", row(&bar, iw).truecolor(80,200,255));
    eprintln!("{}", row("", iw).truecolor(80,200,255));

    // Stats row
    let stats = format!(
        "  {} {} findings    {} {:.2}s    {} 6 engines",
        "📊".truecolor(80,200,255),
        total.to_string().bright_white().bold(),
        "⏱".truecolor(80,200,255),
        elapsed.as_secs_f64(),
        "⚙".truecolor(80,200,255),
    );
    eprintln!("{}", row(&stats, iw).truecolor(80,200,255));
    eprintln!("{}", bot(W).truecolor(80,200,255));
    eprintln!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Rich finding card
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn print_finding(
    index: usize,
    finding: &program_analyzer::VulnerabilityFinding,
) {
    let iw = W - 2;
    let border_color = match finding.severity {
        5 => (239, 68, 68),
        4 => (255, 140, 0),
        3 => (59, 130, 246),
        _ => (100, 116, 139),
    };
    let bc = |s: &str| s.truecolor(border_color.0, border_color.1, border_color.2);

    // Top border
    println!("{}", bc(&thin_top(W)));

    // Header: index + badge + ID + confidence
    let header = format!(
        " #{:<2}  {}  {}  {}",
        index,
        sev_badge(finding.severity),
        finding.id.cyan().bold(),
        conf_bar(finding.confidence),
    );
    println!("{}", bc(&thin_row(&header, iw)));

    // Title
    let title = format!("  {} {}", "→".truecolor(border_color.0, border_color.1, border_color.2), finding.vuln_type.bright_white().bold());
    println!("{}", bc(&thin_row(&title, iw)));

    // Location line
    let mut loc_parts = Vec::new();
    if !finding.location.is_empty() {
        loc_parts.push(format!("{}", finding.location.truecolor(180,180,180)));
    }
    if !finding.function_name.is_empty() {
        loc_parts.push(format!("fn {}", finding.function_name.truecolor(168,85,247)));
    }
    if finding.line_number > 0 {
        loc_parts.push(format!("L{}", finding.line_number.to_string().truecolor(234,179,8)));
    }
    if let Some(ref cwe) = finding.cwe {
        loc_parts.push(format!("{}", cwe.truecolor(6,182,212)));
    }
    if !loc_parts.is_empty() {
        let loc = format!("  {}  {}", "📍".truecolor(100,116,139), loc_parts.join("  ·  "));
        println!("{}", bc(&thin_row(&loc, iw)));
    }

    println!("{}", bc(&thin_mid(W)));

    // Description
    for line in wrap(strip_ansi(&finding.description), iw - 4) {
        println!("{}", bc(&thin_row(&format!("  {}", line.truecolor(180,180,180)), iw)));
    }

    // Code snippet (truncated)
    if !finding.vulnerable_code.is_empty() {
        println!("{}", bc(&thin_row("", iw)));
        let code_label = format!("  {} {}", "▎".truecolor(border_color.0, border_color.1, border_color.2), "Code".truecolor(100,116,139));
        println!("{}", bc(&thin_row(&code_label, iw)));
        let code_text = finding.vulnerable_code.replace('\n', " ↩ ");
        let truncated = if code_text.len() > 120 {
            format!("{}…", &code_text[..117])
        } else {
            code_text
        };
        for line in wrap(truncated, iw - 6) {
            println!("{}", bc(&thin_row(&format!("    {}", line.truecolor(130,200,130)), iw)));
        }
    }

    // Attack scenario
    if !finding.attack_scenario.is_empty() {
        println!("{}", bc(&thin_row("", iw)));
        let atk_label = format!("  {} {}", "⚔".red(), "Attack Scenario".red());
        println!("{}", bc(&thin_row(&atk_label, iw)));
        for line in wrap(strip_ansi(&finding.attack_scenario), iw - 6) {
            println!("{}", bc(&thin_row(&format!("    {}", line.truecolor(160,160,160)), iw)));
        }
    }

    // Real-world incident
    if let Some(ref incident) = finding.real_world_incident {
        let inc = format!(
            "  {} {} — {} ({})",
            "📰".truecolor(234,179,8),
            incident.project.truecolor(234,179,8).bold(),
            incident.loss.red().bold(),
            incident.date.truecolor(100,116,139),
        );
        println!("{}", bc(&thin_row(&inc, iw)));
    }

    // Fix
    if !finding.secure_fix.is_empty() {
        println!("{}", bc(&thin_mid(W)));
        let fix_label = format!("  {} {}", "✏".truecolor(34,197,94), "Recommended Fix".truecolor(34,197,94).bold());
        println!("{}", bc(&thin_row(&fix_label, iw)));
        for line in wrap(strip_ansi(&finding.secure_fix), iw - 6) {
            println!("{}", bc(&thin_row(&format!("    {}", line.truecolor(34,197,94)), iw)));
        }
    }

    println!("{}", bc(&thin_bot(W)));
    println!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Score card
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn print_score_card(score: u8, grade: &str, name: &str) {
    let iw = W - 2;
    let grade_color = match score {
        90..=100 => (34,197,94),
        75..=89 => (234,179,8),
        50..=74 => (255,140,0),
        _ => (239,68,68),
    };

    eprintln!("{}", top(W).truecolor(grade_color.0, grade_color.1, grade_color.2));
    let title = center(&format!("{}", "SECURITY SCORE".bright_white().bold()), iw);
    eprintln!("{}", row(&title, iw).truecolor(grade_color.0, grade_color.1, grade_color.2));
    eprintln!("{}", mid(W).truecolor(grade_color.0, grade_color.1, grade_color.2));

    let big_score = format!(
        "{}  /  100",
        score.to_string().truecolor(grade_color.0, grade_color.1, grade_color.2).bold()
    );
    eprintln!("{}", row(&center(&big_score, iw), iw).truecolor(grade_color.0, grade_color.1, grade_color.2));

    let grade_line = format!(
        "Grade: {}    Program: {}",
        grade.truecolor(grade_color.0, grade_color.1, grade_color.2).bold(),
        name.bright_white(),
    );
    eprintln!("{}", row(&center(&grade_line, iw), iw).truecolor(grade_color.0, grade_color.1, grade_color.2));

    // Score bar
    let filled = (score as usize * 40) / 100;
    let empty = 40 - filled;
    let bar = format!(
        "  {}{}",
        "█".repeat(filled).truecolor(grade_color.0, grade_color.1, grade_color.2),
        "░".repeat(empty).truecolor(60,60,60),
    );
    eprintln!("{}", row(&bar, iw).truecolor(grade_color.0, grade_color.1, grade_color.2));
    eprintln!("{}", bot(W).truecolor(grade_color.0, grade_color.1, grade_color.2));
    eprintln!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Verdict
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
pub fn print_verdict(critical: usize) {
    let iw = W - 2;
    if critical == 0 {
        eprintln!("{}", top(W).truecolor(34,197,94));
        let v = center(&format!("{}", "✓  DEPLOYMENT READY  ✓".truecolor(34,197,94).bold()), iw);
        eprintln!("{}", row(&v, iw).truecolor(34,197,94));
        eprintln!("{}", bot(W).truecolor(34,197,94));
    } else {
        eprintln!("{}", top(W).red());
        let v = center(&format!("{}", "✗  DEPLOYMENT BLOCKED  ✗".red().bold()), iw);
        eprintln!("{}", row(&v, iw).red());
        let reason = center(&format!("{} critical vulnerabilities must be resolved", critical), iw);
        eprintln!("{}", row(&reason, iw).red());
        eprintln!("{}", bot(W).red());
    }
    eprintln!();
}

// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
//  Helpers
// ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

fn wrap(text: String, max_w: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        if cur.len() + word.len() + 1 > max_w && !cur.is_empty() {
            lines.push(cur);
            cur = word.to_string();
        } else {
            if !cur.is_empty() { cur.push(' '); }
            cur.push_str(word);
        }
    }
    if !cur.is_empty() { lines.push(cur); }
    if lines.is_empty() { lines.push(String::new()); }
    lines
}
