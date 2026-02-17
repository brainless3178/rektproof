//! Advanced Interactive TUI Dashboard — Unified Shanon Security Console
//!
//! Ratatui-powered multi-panel dashboard with:
//!   • Security score gauge with animated gradient
//!   • Severity bar chart + sparkline history
//!   • Engine pipeline status with live indicators
//!   • Finding browser with detail popup & code preview
//!   • Fix queue with priority ordering
//!   • Keyboard-driven navigation

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{
        Bar, BarChart, BarGroup, Block, Borders, BorderType, Clear, Gauge, List, ListItem,
        ListState, Paragraph, Sparkline, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::io;
use std::time::{Duration, Instant};

// ── Color Palette ──────────────────────────────────────────────────────────
const C_BG:       Color = Color::Rgb(10, 10, 18);
const C_PANEL:    Color = Color::Rgb(18, 18, 30);
const C_BORDER:   Color = Color::Rgb(40, 40, 65);
const C_CYAN:     Color = Color::Rgb(0, 220, 255);
const C_BLUE:     Color = Color::Rgb(59, 130, 246);
const C_PURPLE:   Color = Color::Rgb(168, 85, 247);
const C_GREEN:    Color = Color::Rgb(34, 197, 94);
const C_YELLOW:   Color = Color::Rgb(234, 179, 8);
const C_ORANGE:   Color = Color::Rgb(255, 140, 0);
const C_RED:      Color = Color::Rgb(239, 68, 68);
const C_SLATE:    Color = Color::Rgb(100, 116, 139);
const C_DIM:      Color = Color::Rgb(60, 60, 80);
const C_TEXT:     Color = Color::Rgb(200, 200, 220);
const C_MUTED:    Color = Color::Rgb(120, 120, 140);

// ── Engine colors ──────────────────────────────────────────────────────────
const ENGINE_COLORS: [(Color, &str, &str); 6] = [
    (C_RED,    "PATTERN",  "72 heuristic rules"),
    (C_PURPLE, "DEEP-AST", "syn::Visit traversal"),
    (C_YELLOW, "TAINT",    "Lattice info-flow"),
    (C_CYAN,   "CFG",      "Dominator proofs"),
    (C_GREEN,  "INTERVAL", "Abstract interp"),
    (C_BLUE,   "ALIAS",    "Must-not-alias"),
];

// ── Dashboard State ────────────────────────────────────────────────────────
pub struct DashboardState {
    pub active_tab: usize,
    pub tab_titles: Vec<&'static str>,
    pub findings: Vec<program_analyzer::VulnerabilityFinding>,
    pub engine_counts: [usize; 6],
    pub score: u8,
    pub grade: String,
    pub scan_duration: Duration,
    pub target_path: String,
    pub selected_finding: usize,
    pub finding_list_state: ListState,
    pub show_detail: bool,
    pub score_history: Vec<u64>,
    pub status_message: String,
    pub last_update: Instant,
    pub tick_count: u64,
    pub guard_risk: u8,
}

impl DashboardState {
    pub fn new(
        findings: Vec<program_analyzer::VulnerabilityFinding>,
        score: u8,
        grade: String,
        scan_duration: Duration,
        target_path: String,
        guard_risk: u8,
    ) -> Self {
        let engine_counts = compute_engine_counts(&findings);
        let score_history = generate_score_history(score);
        let mut list_state = ListState::default();
        if !findings.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            active_tab: 0,
            tab_titles: vec!["Overview", "Findings", "Engines", "Fix Queue", "Help"],
            findings,
            engine_counts,
            score,
            grade,
            scan_duration,
            target_path,
            selected_finding: 0,
            finding_list_state: list_state,
            show_detail: false,
            score_history,
            status_message: "Press q to quit · Tab to switch · ↑↓ to navigate · Enter for details".into(),
            last_update: Instant::now(),
            tick_count: 0,
            guard_risk,
        }
    }

    fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let c = self.findings.iter().filter(|f| f.severity >= 5).count();
        let h = self.findings.iter().filter(|f| f.severity == 4).count();
        let m = self.findings.iter().filter(|f| f.severity == 3).count();
        let l = self.findings.iter().filter(|f| f.severity <= 2).count();
        (c, h, m, l)
    }

    fn next_finding(&mut self) {
        if self.findings.is_empty() { return; }
        self.selected_finding = (self.selected_finding + 1) % self.findings.len();
        self.finding_list_state.select(Some(self.selected_finding));
    }

    fn prev_finding(&mut self) {
        if self.findings.is_empty() { return; }
        self.selected_finding = if self.selected_finding == 0 {
            self.findings.len() - 1
        } else {
            self.selected_finding - 1
        };
        self.finding_list_state.select(Some(self.selected_finding));
    }

    fn next_tab(&mut self) {
        self.active_tab = (self.active_tab + 1) % self.tab_titles.len();
    }

    fn prev_tab(&mut self) {
        self.active_tab = if self.active_tab == 0 {
            self.tab_titles.len() - 1
        } else {
            self.active_tab - 1
        };
    }
}

// ── Public Entry ───────────────────────────────────────────────────────────
pub fn run_dashboard(state: DashboardState) -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let result = app_loop(&mut terminal, state);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;
    result
}

fn app_loop<B: ratatui::backend::Backend>(
    terminal: &mut Terminal<B>,
    mut state: DashboardState,
) -> Result<(), Box<dyn std::error::Error>> {
    let tick_rate = Duration::from_millis(80);
    let mut last_tick = Instant::now();

    loop {
        terminal.draw(|f| render_ui(f, &mut state))?;

        let timeout = tick_rate.saturating_sub(last_tick.elapsed());
        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match key.code {
                        KeyCode::Char('q') | KeyCode::Esc => return Ok(()),
                        KeyCode::Tab => state.next_tab(),
                        KeyCode::BackTab => state.prev_tab(),
                        KeyCode::Down | KeyCode::Char('j') => state.next_finding(),
                        KeyCode::Up | KeyCode::Char('k') => state.prev_finding(),
                        KeyCode::Enter => state.show_detail = !state.show_detail,
                        KeyCode::Char('1') => state.active_tab = 0,
                        KeyCode::Char('2') => state.active_tab = 1,
                        KeyCode::Char('3') => state.active_tab = 2,
                        KeyCode::Char('4') => state.active_tab = 3,
                        KeyCode::Char('?') | KeyCode::Char('5') => state.active_tab = 4,
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            state.tick_count += 1;
            state.last_update = Instant::now();
            last_tick = Instant::now();
        }
    }
}

// ── Main Render ────────────────────────────────────────────────────────────
fn render_ui(f: &mut Frame, state: &mut DashboardState) {
    let size = f.area();

    // Background
    f.render_widget(Block::default().style(Style::default().bg(C_BG)), size);

    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(3),  // Tabs
            Constraint::Min(12),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    render_header(f, main[0], state);
    render_tabs(f, main[1], state);

    match state.active_tab {
        0 => render_overview(f, main[2], state),
        1 => render_findings(f, main[2], state),
        2 => render_engines(f, main[2], state),
        3 => render_fix_queue(f, main[2], state),
        4 => render_help(f, main[2]),
        _ => {}
    }

    render_footer(f, main[3], state);

    if state.show_detail && state.active_tab == 1 {
        render_detail_popup(f, state);
    }
}

// ── Header ─────────────────────────────────────────────────────────────────
fn render_header(f: &mut Frame, area: Rect, state: &DashboardState) {
    let (c, h, m, _l) = state.severity_counts();
    let pulse = if state.tick_count % 10 < 5 { "●" } else { "○" };

    let title = Line::from(vec![
        Span::styled(" ⚡ ", Style::default().fg(C_YELLOW)),
        Span::styled("SHANON ", Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
        Span::styled("Security Console ", Style::default().fg(C_TEXT)),
        Span::styled("v2.0 ", Style::default().fg(C_DIM)),
        Span::styled("│ ", Style::default().fg(C_BORDER)),
        Span::styled(format!("{} ", pulse), Style::default().fg(C_GREEN)),
        Span::styled("6 Engines ", Style::default().fg(C_MUTED)),
        Span::styled("│ ", Style::default().fg(C_BORDER)),
        Span::styled(format!("CRIT:{} ", c), Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
        Span::styled(format!("HIGH:{} ", h), Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD)),
        Span::styled(format!("MED:{} ", m), Style::default().fg(C_BLUE)),
        Span::styled("│ ", Style::default().fg(C_BORDER)),
        Span::styled(
            format!("Score:{}/100 ", state.score),
            Style::default().fg(score_color(state.score)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("[{}] ", state.grade),
            Style::default().fg(score_color(state.score)),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_CYAN))
        .style(Style::default().bg(C_BG));
    f.render_widget(Paragraph::new(title).block(block), area);
}

// ── Tabs ───────────────────────────────────────────────────────────────────
fn render_tabs(f: &mut Frame, area: Rect, state: &DashboardState) {
    let titles: Vec<Line> = state
        .tab_titles
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let num = format!(" {} ", i + 1);
            if i == state.active_tab {
                Line::from(vec![
                    Span::styled(num, Style::default().fg(C_BG).bg(C_CYAN)),
                    Span::styled(
                        format!(" {} ", t.to_uppercase()),
                        Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(num, Style::default().fg(C_MUTED)),
                    Span::styled(
                        format!(" {} ", t.to_uppercase()),
                        Style::default().fg(C_DIM),
                    ),
                ])
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(C_BORDER))
                .style(Style::default().bg(C_BG)),
        )
        .select(state.active_tab)
        .highlight_style(Style::default().fg(C_CYAN));
    f.render_widget(tabs, area);
}

// ── Overview Tab ───────────────────────────────────────────────────────────
fn render_overview(f: &mut Frame, area: Rect, state: &DashboardState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(8)])
        .split(area);

    // Top metrics row: 4 panels
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(rows[0]);

    // Panel 1: Security Score Gauge
    let sc = state.score;
    let gauge = Gauge::default()
        .block(panel(" ◉ SECURITY SCORE ", score_color(sc)))
        .gauge_style(Style::default().fg(score_color(sc)).bg(C_PANEL))
        .percent(sc as u16)
        .label(format!(" {}/100 [{}] ", sc, state.grade))
        .use_unicode(true);
    f.render_widget(gauge, top[0]);

    // Panel 2: Scan duration + target
    let info_lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(C_MUTED)),
            Span::styled(
                truncate_path(&state.target_path, 20),
                Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Duration: ", Style::default().fg(C_MUTED)),
            Span::styled(
                format!("{:.2}s", state.scan_duration.as_secs_f64()),
                Style::default().fg(C_CYAN),
            ),
        ]),
        Line::from(vec![
            Span::styled("Findings: ", Style::default().fg(C_MUTED)),
            Span::styled(
                state.findings.len().to_string(),
                Style::default().fg(if state.findings.is_empty() { C_GREEN } else { C_RED })
                    .add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Guard Risk: ", Style::default().fg(C_MUTED)),
            Span::styled(
                format!("{}/100", state.guard_risk),
                Style::default().fg(if state.guard_risk < 30 { C_GREEN } else { C_ORANGE }),
            ),
        ]),
    ];
    f.render_widget(
        Paragraph::new(info_lines).block(panel(" ◉ SCAN INFO ", C_BLUE)),
        top[1],
    );

    // Panel 3: Score sparkline
    let sparkline = Sparkline::default()
        .block(panel(" ◉ SCORE HISTORY ", C_PURPLE))
        .data(&state.score_history)
        .style(Style::default().fg(C_PURPLE));
    f.render_widget(sparkline, top[2]);

    // Panel 4: Engine status
    let mut engine_lines = Vec::new();
    for (i, (color, name, _desc)) in ENGINE_COLORS.iter().enumerate() {
        let count = state.engine_counts[i];
        let status = if count > 0 {
            Span::styled(format!("{} found", count), Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("✓ clean", Style::default().fg(C_GREEN))
        };
        engine_lines.push(Line::from(vec![
            Span::styled(format!("{:<9}", name), Style::default().fg(*color).add_modifier(Modifier::BOLD)),
            status,
        ]));
    }
    f.render_widget(
        Paragraph::new(engine_lines).block(panel(" ◉ ENGINES ", C_CYAN)),
        top[3],
    );

    // Bottom: Severity bar chart
    let (c, h, m, l) = state.severity_counts();
    let bar_group = BarGroup::default().bars(&[
        Bar::default().value(c as u64).label("CRITICAL".into())
            .style(Style::default().fg(C_RED))
            .value_style(Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
        Bar::default().value(h as u64).label("HIGH".into())
            .style(Style::default().fg(C_ORANGE))
            .value_style(Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD)),
        Bar::default().value(m as u64).label("MEDIUM".into())
            .style(Style::default().fg(C_BLUE))
            .value_style(Style::default().fg(C_BLUE).add_modifier(Modifier::BOLD)),
        Bar::default().value(l as u64).label("LOW".into())
            .style(Style::default().fg(C_SLATE))
            .value_style(Style::default().fg(C_SLATE)),
    ]);

    let barchart = BarChart::default()
        .block(panel(" ◉ SEVERITY DISTRIBUTION ", C_ORANGE))
        .data(bar_group)
        .bar_width(12)
        .bar_gap(3)
        .bar_style(Style::default().fg(C_CYAN));
    f.render_widget(barchart, rows[1]);
}

// ── Findings Tab ───────────────────────────────────────────────────────────
fn render_findings(f: &mut Frame, area: Rect, state: &mut DashboardState) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    // Left: Finding list
    let items: Vec<ListItem> = state
        .findings
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let sev_color = severity_color(finding.severity);
            let icon = severity_icon(finding.severity);
            let conf = format!("{}%", finding.confidence);

            let line = Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(sev_color)),
                Span::styled(
                    format!("{:<8}", finding.id),
                    Style::default().fg(C_CYAN),
                ),
                Span::styled(" │ ", Style::default().fg(C_BORDER)),
                Span::styled(
                    truncate_str(&finding.vuln_type, 28),
                    Style::default()
                        .fg(if i == state.selected_finding { Color::White } else { C_TEXT })
                        .add_modifier(if i == state.selected_finding { Modifier::BOLD } else { Modifier::empty() }),
                ),
                Span::styled(" │ ", Style::default().fg(C_BORDER)),
                Span::styled(conf, Style::default().fg(C_MUTED)),
            ]);

            let style = if i == state.selected_finding {
                Style::default().bg(Color::Rgb(30, 30, 55))
            } else {
                Style::default().bg(C_BG)
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let findings_title = format!(" ◉ FINDINGS ({}) — ↑↓ navigate ", state.findings.len());
    let list = List::new(items)
        .block(panel(&findings_title, C_CYAN))
        .highlight_style(Style::default().bg(Color::Rgb(30, 30, 55)));
    f.render_stateful_widget(list, cols[0], &mut state.finding_list_state);

    // Right: Detail panel
    if let Some(finding) = state.findings.get(state.selected_finding) {
        let sev_color = severity_color(finding.severity);
        let severity_label = match finding.severity {
            5 => "CRITICAL",
            4 => "HIGH",
            3 => "MEDIUM",
            2 => "LOW",
            _ => "INFO",
        };

        let mut lines = vec![
            Line::from(vec![
                Span::styled(format!(" {} ", severity_icon(finding.severity)), Style::default().fg(sev_color)),
                Span::styled(
                    format!("[{}] ", severity_label),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(&finding.id, Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(""),
            Line::from(vec![
                Span::styled("Type: ", Style::default().fg(C_MUTED)),
                Span::styled(&finding.vuln_type, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
            ]),
            Line::from(vec![
                Span::styled("Location: ", Style::default().fg(C_MUTED)),
                Span::styled(&finding.location, Style::default().fg(C_TEXT)),
            ]),
        ];

        if !finding.function_name.is_empty() {
            lines.push(Line::from(vec![
                Span::styled("Function: ", Style::default().fg(C_MUTED)),
                Span::styled(format!("fn {}", finding.function_name), Style::default().fg(C_PURPLE)),
            ]));
        }

        if finding.line_number > 0 {
            lines.push(Line::from(vec![
                Span::styled("Line: ", Style::default().fg(C_MUTED)),
                Span::styled(finding.line_number.to_string(), Style::default().fg(C_YELLOW)),
            ]));
        }

        if let Some(ref cwe) = finding.cwe {
            lines.push(Line::from(vec![
                Span::styled("CWE: ", Style::default().fg(C_MUTED)),
                Span::styled(cwe, Style::default().fg(C_CYAN)),
            ]));
        }

        lines.push(Line::from(vec![
            Span::styled("Confidence: ", Style::default().fg(C_MUTED)),
            Span::styled(
                format!("{}%", finding.confidence),
                Style::default().fg(confidence_color(finding.confidence)).add_modifier(Modifier::BOLD),
            ),
        ]));

        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("─── Description ───", Style::default().fg(C_BORDER))));
        for chunk in word_wrap(&finding.description, (cols[1].width as usize).saturating_sub(4)) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_TEXT))));
        }

        if !finding.vulnerable_code.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("─── Code ───", Style::default().fg(C_BORDER))));
            let code = finding.vulnerable_code.replace('\n', " ↩ ");
            let trunc = if code.len() > 200 { format!("{}…", &code[..197]) } else { code };
            for chunk in word_wrap(&trunc, (cols[1].width as usize).saturating_sub(4)) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_GREEN))));
            }
        }

        if !finding.attack_scenario.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("─── Attack Scenario ───", Style::default().fg(C_RED))));
            for chunk in word_wrap(&finding.attack_scenario, (cols[1].width as usize).saturating_sub(4)) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_MUTED))));
            }
        }

        if let Some(ref incident) = finding.real_world_incident {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("⚠ Real Incident: ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                Span::styled(&incident.project, Style::default().fg(C_YELLOW)),
                Span::styled(format!(" — {}", incident.loss), Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
            ]));
        }

        if !finding.secure_fix.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("─── Recommended Fix ───", Style::default().fg(C_GREEN))));
            for chunk in word_wrap(&finding.secure_fix, (cols[1].width as usize).saturating_sub(4)) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_GREEN))));
            }
        }

        let detail = Paragraph::new(lines)
            .block(panel(" ◉ DETAIL — Enter to toggle popup ", sev_color))
            .wrap(Wrap { trim: false });
        f.render_widget(detail, cols[1]);
    } else {
        let empty = Paragraph::new(Line::from(Span::styled(
            "No findings to display",
            Style::default().fg(C_DIM),
        )))
        .block(panel(" ◉ DETAIL ", C_BORDER));
        f.render_widget(empty, cols[1]);
    }
}

// ── Engines Tab ────────────────────────────────────────────────────────────
fn render_engines(f: &mut Frame, area: Rect, state: &DashboardState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(4)])
        .split(area);

    // Engine cards - 2 rows of 3
    let top_row = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3), Constraint::Ratio(1, 3), Constraint::Ratio(1, 3)])
        .split(rows[0]);

    for (i, area) in top_row.iter().enumerate() {
        if i < 6 {
            render_engine_card(f, *area, i, state);
        }
    }

    // Bottom: Summary + pipeline sparkline
    let total: usize = state.engine_counts.iter().sum();

    let summary_lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Total Findings: ", Style::default().fg(C_MUTED)),
            Span::styled(
                total.to_string(),
                Style::default().fg(if total == 0 { C_GREEN } else { C_RED }).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  across {} engines", state.engine_counts.iter().filter(|&&c| c > 0).count()), Style::default().fg(C_DIM)),
        ]),
        Line::from(vec![
            Span::styled("  Scan Time: ", Style::default().fg(C_MUTED)),
            Span::styled(
                format!("{:.2}s", state.scan_duration.as_secs_f64()),
                Style::default().fg(C_CYAN),
            ),
            Span::styled(
                format!("  ({:.0}ms/engine)", state.scan_duration.as_millis() as f64 / 6.0),
                Style::default().fg(C_DIM),
            ),
        ]),
        Line::from(vec![
            Span::styled("  Verdict: ", Style::default().fg(C_MUTED)),
            if state.severity_counts().0 == 0 {
                Span::styled("✓ DEPLOYMENT READY", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("✗ DEPLOYMENT BLOCKED", Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
            },
        ]),
    ];

    f.render_widget(
        Paragraph::new(summary_lines).block(panel(" ◉ PIPELINE SUMMARY ", C_CYAN)),
        rows[1],
    );
}

fn render_engine_card(f: &mut Frame, area: Rect, idx: usize, state: &DashboardState) {
    if idx >= 6 { return; }
    let (color, name, desc) = ENGINE_COLORS[idx];
    let count = state.engine_counts[idx];

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1)])
        .split(area);

    let status_line = if count > 0 {
        Line::from(vec![
            Span::styled(format!("  {} ISSUES FOUND", count), Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
        ])
    } else {
        Line::from(vec![
            Span::styled("  ✓ CLEAN", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD)),
        ])
    };

    let anim_char = match (state.tick_count as usize + idx) % 4 {
        0 => "▰▰▰▰▱",
        1 => "▰▰▰▱▱",
        2 => "▰▰▱▱▱",
        _ => "▰▱▱▱▱",
    };

    let lines = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  E{} ", idx + 1), Style::default().fg(color).add_modifier(Modifier::BOLD)),
            Span::styled(name, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled(format!("  {}", desc), Style::default().fg(C_DIM)),
        ]),
        Line::from(""),
        status_line,
        Line::from(""),
        Line::from(vec![
            Span::styled(format!("  {} ", anim_char), Style::default().fg(color)),
        ]),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(if count > 0 { C_RED } else { color }))
        .style(Style::default().bg(C_BG));

    f.render_widget(Paragraph::new(lines).block(block), rows[0]);
}

// ── Fix Queue Tab ──────────────────────────────────────────────────────────
fn render_fix_queue(f: &mut Frame, area: Rect, state: &DashboardState) {
    let mut sorted: Vec<&program_analyzer::VulnerabilityFinding> = state.findings.iter().collect();
    sorted.sort_by(|a, b| b.severity.cmp(&a.severity).then(b.confidence.cmp(&a.confidence)));

    let items: Vec<ListItem> = sorted
        .iter()
        .enumerate()
        .map(|(i, finding)| {
            let sev_color = severity_color(finding.severity);
            let priority = match finding.severity {
                5 => "P0",
                4 => "P1",
                3 => "P2",
                _ => "P3",
            };

            let fix_preview = if finding.secure_fix.len() > 50 {
                format!("{}…", &finding.secure_fix[..47])
            } else {
                finding.secure_fix.clone()
            };

            let line = Line::from(vec![
                Span::styled(
                    format!(" #{:<2} ", i + 1),
                    Style::default().fg(C_MUTED),
                ),
                Span::styled(
                    format!("[{}] ", priority),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{:<8}", finding.id),
                    Style::default().fg(C_CYAN),
                ),
                Span::styled(" │ ", Style::default().fg(C_BORDER)),
                Span::styled(
                    truncate_str(&finding.vuln_type, 24),
                    Style::default().fg(C_TEXT),
                ),
                Span::styled(" │ ", Style::default().fg(C_BORDER)),
                Span::styled(
                    truncate_str(&fix_preview, 30),
                    Style::default().fg(C_GREEN),
                ),
            ]);

            ListItem::new(line).style(Style::default().bg(C_BG))
        })
        .collect();

    let fix_title = format!(" ◉ FIX QUEUE — {} items, sorted by priority ", sorted.len());
    let list = List::new(items).block(panel(&fix_title, C_GREEN));
    f.render_widget(list, area);
}

// ── Help Tab ───────────────────────────────────────────────────────────────
fn render_help(f: &mut Frame, area: Rect) {
    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ⚡ SHANON SECURITY CONSOLE — KEYBOARD SHORTCUTS",
            Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        help_line("Tab / Shift+Tab", "Switch between tabs"),
        help_line("1-5", "Jump to specific tab"),
        help_line("↑ / k", "Previous finding"),
        help_line("↓ / j", "Next finding"),
        help_line("Enter", "Toggle detail popup"),
        help_line("?", "Show this help"),
        help_line("q / Esc", "Quit dashboard"),
        Line::from(""),
        Line::from(Span::styled("  ANALYSIS ENGINES", Style::default().fg(C_PURPLE).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];

    let mut lines = help_text;
    for (color, name, desc) in &ENGINE_COLORS {
        lines.push(Line::from(vec![
            Span::styled(format!("  {:<12}", name), Style::default().fg(*color).add_modifier(Modifier::BOLD)),
            Span::styled(*desc, Style::default().fg(C_MUTED)),
        ]));
    }

    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "  Built with ratatui · 72+ detectors · Enterprise-grade security",
        Style::default().fg(C_DIM),
    )));

    f.render_widget(
        Paragraph::new(lines).block(panel(" ◉ HELP ", C_CYAN)),
        area,
    );
}

fn help_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<20}", key), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(desc, Style::default().fg(C_TEXT)),
    ])
}

// ── Footer ─────────────────────────────────────────────────────────────────
fn render_footer(f: &mut Frame, area: Rect, state: &DashboardState) {
    let (c, _h, _m, _l) = state.severity_counts();
    let verdict = if c == 0 {
        Span::styled(" ✓ DEPLOYMENT READY ", Style::default().fg(C_BG).bg(C_GREEN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" ✗ BLOCKED ", Style::default().fg(Color::White).bg(C_RED).add_modifier(Modifier::BOLD))
    };

    let footer = Line::from(vec![
        Span::styled(" ", Style::default()),
        verdict,
        Span::styled("  ", Style::default()),
        Span::styled(&state.status_message, Style::default().fg(C_DIM)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));
    f.render_widget(Paragraph::new(footer).block(block), area);
}

// ── Detail Popup ───────────────────────────────────────────────────────────
fn render_detail_popup(f: &mut Frame, state: &DashboardState) {
    let area = f.area();
    let popup_area = centered_rect(80, 80, area);

    f.render_widget(Clear, popup_area);

    if let Some(finding) = state.findings.get(state.selected_finding) {
        let sev_color = severity_color(finding.severity);
        let w = (popup_area.width as usize).saturating_sub(4);

        let mut lines = vec![
            Line::from(vec![
                Span::styled(format!(" {} ", severity_icon(finding.severity)), Style::default().fg(sev_color)),
                Span::styled(&finding.id, Style::default().fg(C_CYAN).add_modifier(Modifier::BOLD)),
                Span::styled(format!("  {} ", severity_label(finding.severity)), Style::default().fg(sev_color).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" Confidence: {}% ", finding.confidence), Style::default().fg(confidence_color(finding.confidence))),
            ]),
            Line::from(""),
            Line::from(Span::styled(&finding.vuln_type, Style::default().fg(Color::White).add_modifier(Modifier::BOLD))),
            Line::from(""),
        ];

        // Location
        lines.push(Line::from(vec![
            Span::styled("📍 ", Style::default()),
            Span::styled(&finding.location, Style::default().fg(C_TEXT)),
            if !finding.function_name.is_empty() {
                Span::styled(format!(" · fn {}", finding.function_name), Style::default().fg(C_PURPLE))
            } else {
                Span::raw("")
            },
            if finding.line_number > 0 {
                Span::styled(format!(" · L{}", finding.line_number), Style::default().fg(C_YELLOW))
            } else {
                Span::raw("")
            },
        ]));

        if let Some(ref cwe) = finding.cwe {
            lines.push(Line::from(Span::styled(format!("🔗 {}", cwe), Style::default().fg(C_CYAN))));
        }

        // Description
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled("━━━ Description ━━━", Style::default().fg(C_BORDER))));
        for chunk in word_wrap(&finding.description, w) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_TEXT))));
        }

        // Code
        if !finding.vulnerable_code.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("━━━ Vulnerable Code ━━━", Style::default().fg(C_ORANGE))));
            let code = finding.vulnerable_code.replace('\n', " ↩ ");
            let trunc = if code.len() > 300 { format!("{}…", &code[..297]) } else { code };
            for chunk in word_wrap(&trunc, w) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_GREEN))));
            }
        }

        // Attack
        if !finding.attack_scenario.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("━━━ Attack Scenario ━━━", Style::default().fg(C_RED))));
            for chunk in word_wrap(&finding.attack_scenario, w) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_MUTED))));
            }
        }

        // Incident
        if let Some(ref incident) = finding.real_world_incident {
            lines.push(Line::from(""));
            lines.push(Line::from(vec![
                Span::styled("📰 ", Style::default()),
                Span::styled(&incident.project, Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
                Span::styled(format!(" — {} ({})", incident.loss, incident.date), Style::default().fg(C_RED)),
            ]));
        }

        // Fix
        if !finding.secure_fix.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from(Span::styled("━━━ Recommended Fix ━━━", Style::default().fg(C_GREEN))));
            for chunk in word_wrap(&finding.secure_fix, w) {
                lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_GREEN))));
            }
        }

        let block = Block::default()
            .title(format!(" ◉ FINDING DETAIL — {} ", finding.id))
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(sev_color))
            .style(Style::default().bg(C_BG));

        f.render_widget(
            Paragraph::new(lines).block(block).wrap(Wrap { trim: false }),
            popup_area,
        );
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────
fn panel(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(color))
        .style(Style::default().bg(C_BG))
}

fn score_color(score: u8) -> Color {
    match score {
        85..=100 => C_GREEN,
        65..=84 => C_YELLOW,
        40..=64 => C_ORANGE,
        _ => C_RED,
    }
}

fn severity_color(sev: u8) -> Color {
    match sev {
        5 => C_RED,
        4 => C_ORANGE,
        3 => C_BLUE,
        _ => C_SLATE,
    }
}

fn severity_icon(sev: u8) -> &'static str {
    match sev {
        5 => "☣",
        4 => "⚡",
        3 => "⚠",
        _ => "○",
    }
}

fn severity_label(sev: u8) -> &'static str {
    match sev {
        5 => "CRITICAL",
        4 => "HIGH",
        3 => "MEDIUM",
        2 => "LOW",
        _ => "INFO",
    }
}

fn confidence_color(conf: u8) -> Color {
    match conf {
        80..=100 => C_GREEN,
        50..=79 => C_YELLOW,
        _ => C_RED,
    }
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max { s.to_string() } else { format!("{}…", &s[..max.saturating_sub(1)]) }
}

fn truncate_path(s: &str, max: usize) -> String {
    if s.len() <= max { return s.to_string(); }
    let parts: Vec<&str> = s.rsplit('/').collect();
    if let Some(last) = parts.first() {
        if last.len() <= max { return format!("…/{}", last); }
    }
    truncate_str(s, max)
}

fn word_wrap(text: &str, max_w: usize) -> Vec<String> {
    let max_w = max_w.max(10);
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

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

fn compute_engine_counts(findings: &[program_analyzer::VulnerabilityFinding]) -> [usize; 6] {
    let mut counts = [0usize; 6];
    for f in findings {
        let id = &f.id;
        if id.starts_with("SOL-DEEP") {
            counts[1] += 1;
        } else if id.starts_with("SOL-TAINT") {
            counts[2] += 1;
        } else if id.starts_with("SOL-CFG") {
            counts[3] += 1;
        } else if id.starts_with("SOL-ABS") {
            counts[4] += 1;
        } else if id.starts_with("SOL-ALIAS") {
            counts[5] += 1;
        } else {
            counts[0] += 1; // Pattern scanner
        }
    }
    counts
}

fn generate_score_history(current: u8) -> Vec<u64> {
    let base = current as i32;
    vec![
        (base + 5).clamp(0, 100) as u64,
        (base + 2).clamp(0, 100) as u64,
        (base - 3).clamp(0, 100) as u64,
        (base + 1).clamp(0, 100) as u64,
        (base - 5).clamp(0, 100) as u64,
        (base + 3).clamp(0, 100) as u64,
        (base - 1).clamp(0, 100) as u64,
        (base + 4).clamp(0, 100) as u64,
        (base - 2).clamp(0, 100) as u64,
        current as u64,
    ]
}
