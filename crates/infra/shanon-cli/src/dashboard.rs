// Interactive TUI dashboard for scan results.
// Ratatui-powered with multi-tab layout, severity filtering, scrollable
// detail views, category heatmap, CWE breakdown, and phase timeline.

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
        ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs, Wrap,
    },
    Frame, Terminal,
};
use std::collections::HashMap;
use std::io;
use std::time::{Duration, Instant};

// Color palette - dark theme with neon accents
const C_BG: Color = Color::Rgb(10, 10, 18);
const C_PANEL: Color = Color::Rgb(18, 18, 30);
const C_BORDER: Color = Color::Rgb(40, 40, 65);
const C_ACCENT: Color = Color::Rgb(0, 220, 255);
const C_BLUE: Color = Color::Rgb(59, 130, 246);
const C_PURPLE: Color = Color::Rgb(168, 85, 247);
const C_GREEN: Color = Color::Rgb(34, 197, 94);
const C_YELLOW: Color = Color::Rgb(234, 179, 8);
const C_ORANGE: Color = Color::Rgb(255, 140, 0);
const C_RED: Color = Color::Rgb(239, 68, 68);
const C_SLATE: Color = Color::Rgb(100, 116, 139);
const C_DIM: Color = Color::Rgb(60, 60, 80);
const C_TEXT: Color = Color::Rgb(200, 200, 220);
const C_MUTED: Color = Color::Rgb(120, 120, 140);
const C_HIGHLIGHT: Color = Color::Rgb(30, 30, 55);

// Phase metadata: (color, short_name, description)
const PHASES: [(Color, &str, &str); 10] = [
    (C_RED, "PATTERN", "72 heuristic rules"),
    (C_PURPLE, "DEEP-AST", "syn::Visit traversal"),
    (C_YELLOW, "TAINT", "Lattice info-flow"),
    (Color::Rgb(0, 200, 200), "CFG", "Dominator proofs"),
    (C_GREEN, "INTERVAL", "Abstract interp"),
    (C_BLUE, "ALIAS", "Must-not-alias"),
    (C_ORANGE, "SEC3", "Soteria checks"),
    (Color::Rgb(200, 100, 200), "ANCHOR", "Constraint verify"),
    (Color::Rgb(100, 200, 100), "DATAFLOW", "Use-def chains"),
    (Color::Rgb(200, 200, 100), "FV/Z3", "Formal verification"),
];

pub struct DashboardState {
    pub active_tab: usize,
    pub tab_titles: Vec<&'static str>,
    pub findings: Vec<program_analyzer::VulnerabilityFinding>,
    pub score: u8,
    pub grade: String,
    pub scan_duration: Duration,
    pub target_path: String,
    pub selected_finding: usize,
    pub finding_list_state: ListState,
    pub show_detail: bool,
    pub tick_count: u64,
    pub guard_risk: u8,
    // Severity filter: [critical, high, medium, low, info]
    pub sev_filter: [bool; 5],
    // Detail scroll offset
    pub detail_scroll: u16,
    // Cached category counts
    pub category_counts: HashMap<String, usize>,
    pub cwe_counts: HashMap<String, usize>,
    pub phase_counts: [usize; 10],
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
        let category_counts = compute_category_counts(&findings);
        let cwe_counts = compute_cwe_counts(&findings);
        let phase_counts = compute_phase_counts(&findings);
        let mut list_state = ListState::default();
        if !findings.is_empty() {
            list_state.select(Some(0));
        }
        Self {
            active_tab: 0,
            tab_titles: vec!["Overview", "Findings", "Engines", "Fixes", "Help"],
            findings,
            score,
            grade,
            scan_duration,
            target_path,
            selected_finding: 0,
            finding_list_state: list_state,
            show_detail: false,
            tick_count: 0,
            guard_risk,
            sev_filter: [true; 5],
            detail_scroll: 0,
            category_counts,
            cwe_counts,
            phase_counts,
        }
    }

    fn severity_counts(&self) -> (usize, usize, usize, usize) {
        let (mut c, mut h, mut m, mut l) = (0, 0, 0, 0);
        for f in &self.findings {
            match f.severity {
                5 => c += 1,
                4 => h += 1,
                3 => m += 1,
                _ => l += 1,
            }
        }
        (c, h, m, l)
    }

    fn filtered_findings(&self) -> Vec<(usize, &program_analyzer::VulnerabilityFinding)> {
        self.findings
            .iter()
            .enumerate()
            .filter(|(_, f)| {
                let idx = match f.severity {
                    5 => 0,
                    4 => 1,
                    3 => 2,
                    2 => 3,
                    _ => 4,
                };
                self.sev_filter[idx]
            })
            .collect()
    }

    fn next_finding(&mut self) {
        let filtered = self.filtered_findings();
        if filtered.is_empty() { return; }
        let cur_pos = filtered.iter().position(|(i, _)| *i == self.selected_finding);
        let next = match cur_pos {
            Some(p) if p + 1 < filtered.len() => filtered[p + 1].0,
            _ => filtered[0].0,
        };
        self.selected_finding = next;
        self.finding_list_state.select(Some(next));
        self.detail_scroll = 0;
    }

    fn prev_finding(&mut self) {
        let filtered = self.filtered_findings();
        if filtered.is_empty() { return; }
        let cur_pos = filtered.iter().position(|(i, _)| *i == self.selected_finding);
        let prev = match cur_pos {
            Some(0) | None => filtered[filtered.len() - 1].0,
            Some(p) => filtered[p - 1].0,
        };
        self.selected_finding = prev;
        self.finding_list_state.select(Some(prev));
        self.detail_scroll = 0;
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

    fn toggle_severity(&mut self, level: usize) {
        if level < 5 {
            self.sev_filter[level] = !self.sev_filter[level];
        }
    }
}

// Public entry point
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
                        KeyCode::Down | KeyCode::Char('j') => {
                            if state.active_tab == 1 {
                                state.next_finding();
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if state.active_tab == 1 {
                                state.prev_finding();
                            }
                        }
                        KeyCode::Enter => state.show_detail = !state.show_detail,
                        KeyCode::Char('1') => state.active_tab = 0,
                        KeyCode::Char('2') => state.active_tab = 1,
                        KeyCode::Char('3') => state.active_tab = 2,
                        KeyCode::Char('4') => state.active_tab = 3,
                        KeyCode::Char('?') | KeyCode::Char('5') => state.active_tab = 4,
                        // Severity filters (F1-F5 or c/h/m/l/i)
                        KeyCode::Char('c') => state.toggle_severity(0),
                        KeyCode::Char('h') => state.toggle_severity(1),
                        KeyCode::Char('m') => state.toggle_severity(2),
                        KeyCode::Char('l') => state.toggle_severity(3),
                        KeyCode::Char('i') => state.toggle_severity(4),
                        // Detail scroll
                        KeyCode::Char('d') => {
                            state.detail_scroll = state.detail_scroll.saturating_add(3);
                        }
                        KeyCode::Char('u') => {
                            state.detail_scroll = state.detail_scroll.saturating_sub(3);
                        }
                        _ => {}
                    }
                }
            }
        }

        if last_tick.elapsed() >= tick_rate {
            state.tick_count += 1;
            last_tick = Instant::now();
        }
    }
}

fn render_ui(f: &mut Frame, state: &mut DashboardState) {
    let size = f.area();
    f.render_widget(Block::default().style(Style::default().bg(C_BG)), size);

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Header
            Constraint::Length(3),  // Tabs
            Constraint::Min(10),   // Content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    render_header(f, layout[0], state);
    render_tabs(f, layout[1], state);

    match state.active_tab {
        0 => render_overview(f, layout[2], state),
        1 => render_findings(f, layout[2], state),
        2 => render_engines(f, layout[2], state),
        3 => render_fix_queue(f, layout[2], state),
        4 => render_help(f, layout[2]),
        _ => {}
    }

    render_footer(f, layout[3], state);

    if state.show_detail && state.active_tab == 1 {
        render_detail_popup(f, state);
    }
}

// ── Header ──────────────────────────────────────────────────────────────

fn render_header(f: &mut Frame, area: Rect, state: &DashboardState) {
    let (c, h, m, _l) = state.severity_counts();
    let pulse = [".", "o", "O", "o"][state.tick_count as usize % 4];

    let title = Line::from(vec![
        Span::styled(" SHANON ", Style::default().fg(C_BG).bg(C_ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled(" Security Console ", Style::default().fg(C_TEXT)),
        Span::styled("v2.0 ", Style::default().fg(C_DIM)),
        Span::styled("| ", Style::default().fg(C_BORDER)),
        Span::styled(format!("{} ", pulse), Style::default().fg(C_GREEN)),
        Span::styled("20 Phases ", Style::default().fg(C_MUTED)),
        Span::styled("| ", Style::default().fg(C_BORDER)),
        Span::styled(format!("C:{} ", c), Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
        Span::styled(format!("H:{} ", h), Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD)),
        Span::styled(format!("M:{} ", m), Style::default().fg(C_BLUE)),
        Span::styled("| ", Style::default().fg(C_BORDER)),
        Span::styled(
            format!("{}/100 ", state.score),
            Style::default().fg(score_color(state.score)).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("[{}]", state.grade),
            Style::default().fg(score_color(state.score)),
        ),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Thick)
        .border_style(Style::default().fg(C_ACCENT))
        .style(Style::default().bg(C_BG));
    f.render_widget(Paragraph::new(title).block(block), area);
}

// ── Tab Bar ─────────────────────────────────────────────────────────────

fn render_tabs(f: &mut Frame, area: Rect, state: &DashboardState) {
    let titles: Vec<Line> = state
        .tab_titles
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let num = format!(" {} ", i + 1);
            if i == state.active_tab {
                Line::from(vec![
                    Span::styled(num, Style::default().fg(C_BG).bg(C_ACCENT)),
                    Span::styled(
                        format!(" {} ", t.to_uppercase()),
                        Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(num, Style::default().fg(C_MUTED)),
                    Span::styled(format!(" {} ", t.to_uppercase()), Style::default().fg(C_DIM)),
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
        .highlight_style(Style::default().fg(C_ACCENT));
    f.render_widget(tabs, area);
}

// ── Overview Tab ────────────────────────────────────────────────────────

fn render_overview(f: &mut Frame, area: Rect, state: &DashboardState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(6)])
        .split(area);

    // Top row: 4 metric panels
    let top = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(rows[0]);

    // Panel 1: Score gauge
    let sc = state.score;
    let gauge = Gauge::default()
        .block(panel("SCORE", score_color(sc)))
        .gauge_style(Style::default().fg(score_color(sc)).bg(C_PANEL))
        .percent(sc as u16)
        .label(format!("{}/100 [{}]", sc, state.grade))
        .use_unicode(true);
    f.render_widget(gauge, top[0]);

    // Panel 2: Scan info
    let info_lines = vec![
        Line::from(vec![
            Span::styled("Target: ", Style::default().fg(C_MUTED)),
            Span::styled(
                truncate_path(&state.target_path, 20),
                Style::default().fg(C_TEXT).add_modifier(Modifier::BOLD),
            ),
        ]),
        Line::from(vec![
            Span::styled("Time:   ", Style::default().fg(C_MUTED)),
            Span::styled(format!("{:.2}s", state.scan_duration.as_secs_f64()), Style::default().fg(C_ACCENT)),
        ]),
        Line::from(vec![
            Span::styled("Total:  ", Style::default().fg(C_MUTED)),
            Span::styled(
                state.findings.len().to_string(),
                Style::default()
                    .fg(if state.findings.is_empty() { C_GREEN } else { C_RED })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(" findings", Style::default().fg(C_MUTED)),
        ]),
        Line::from(vec![
            Span::styled("Guard:  ", Style::default().fg(C_MUTED)),
            Span::styled(
                format!("{}/100", state.guard_risk),
                Style::default().fg(if state.guard_risk < 30 { C_GREEN } else { C_ORANGE }),
            ),
        ]),
    ];
    f.render_widget(Paragraph::new(info_lines).block(panel("SCAN INFO", C_BLUE)), top[1]);

    // Panel 3: Category heatmap
    let mut cat_lines = Vec::new();
    let mut sorted_cats: Vec<_> = state.category_counts.iter().collect();
    sorted_cats.sort_by(|a, b| b.1.cmp(a.1));
    for (cat, count) in sorted_cats.iter().take(4) {
        let bar_len = (**count as usize).min(12);
        let bar: String = "█".repeat(bar_len);
        let color = if **count >= 3 { C_RED } else if **count >= 1 { C_ORANGE } else { C_GREEN };
        cat_lines.push(Line::from(vec![
            Span::styled(format!("{:<12}", truncate_str(cat, 12)), Style::default().fg(C_TEXT)),
            Span::styled(bar, Style::default().fg(color)),
            Span::styled(format!(" {}", count), Style::default().fg(C_MUTED)),
        ]));
    }
    if cat_lines.is_empty() {
        cat_lines.push(Line::from(Span::styled("No findings", Style::default().fg(C_GREEN))));
    }
    f.render_widget(Paragraph::new(cat_lines).block(panel("CATEGORIES", C_PURPLE)), top[2]);

    // Panel 4: CWE breakdown (top 4)
    let mut cwe_lines = Vec::new();
    let mut sorted_cwes: Vec<_> = state.cwe_counts.iter().collect();
    sorted_cwes.sort_by(|a, b| b.1.cmp(a.1));
    for (cwe, count) in sorted_cwes.iter().take(4) {
        let bar_len = (**count as usize).min(10);
        let bar: String = "▓".repeat(bar_len);
        cwe_lines.push(Line::from(vec![
            Span::styled(format!("{:<10}", cwe), Style::default().fg(C_ACCENT)),
            Span::styled(bar, Style::default().fg(C_BLUE)),
            Span::styled(format!(" {}", count), Style::default().fg(C_MUTED)),
        ]));
    }
    if cwe_lines.is_empty() {
        cwe_lines.push(Line::from(Span::styled("No CWEs", Style::default().fg(C_GREEN))));
    }
    f.render_widget(Paragraph::new(cwe_lines).block(panel("CWE MAP", C_ACCENT)), top[3]);

    // Bottom: Severity + confidence distribution
    let bottom = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(rows[1]);

    // Severity bar chart
    let (c, h, m, l) = state.severity_counts();
    let bar_group = BarGroup::default().bars(&[
        Bar::default()
            .value(c as u64)
            .label("CRIT".into())
            .style(Style::default().fg(C_RED))
            .value_style(Style::default().fg(C_RED).add_modifier(Modifier::BOLD)),
        Bar::default()
            .value(h as u64)
            .label("HIGH".into())
            .style(Style::default().fg(C_ORANGE))
            .value_style(Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD)),
        Bar::default()
            .value(m as u64)
            .label("MED".into())
            .style(Style::default().fg(C_BLUE))
            .value_style(Style::default().fg(C_BLUE)),
        Bar::default()
            .value(l as u64)
            .label("LOW".into())
            .style(Style::default().fg(C_SLATE))
            .value_style(Style::default().fg(C_SLATE)),
    ]);

    let barchart = BarChart::default()
        .block(panel("SEVERITY", C_ORANGE))
        .data(bar_group)
        .bar_width(10)
        .bar_gap(2)
        .bar_style(Style::default().fg(C_ACCENT));
    f.render_widget(barchart, bottom[0]);

    // Confidence distribution
    let mut conf_buckets = [0u64; 5]; // 0-20, 21-40, 41-60, 61-80, 81-100
    for finding in &state.findings {
        let idx = match finding.confidence {
            0..=20 => 0,
            21..=40 => 1,
            41..=60 => 2,
            61..=80 => 3,
            _ => 4,
        };
        conf_buckets[idx] += 1;
    }
    let conf_group = BarGroup::default().bars(&[
        Bar::default().value(conf_buckets[0]).label("0-20".into()).style(Style::default().fg(C_RED)),
        Bar::default().value(conf_buckets[1]).label("21-40".into()).style(Style::default().fg(C_ORANGE)),
        Bar::default().value(conf_buckets[2]).label("41-60".into()).style(Style::default().fg(C_YELLOW)),
        Bar::default().value(conf_buckets[3]).label("61-80".into()).style(Style::default().fg(C_BLUE)),
        Bar::default().value(conf_buckets[4]).label("81+".into()).style(Style::default().fg(C_GREEN)),
    ]);
    let conf_chart = BarChart::default()
        .block(panel("CONFIDENCE", C_GREEN))
        .data(conf_group)
        .bar_width(7)
        .bar_gap(1);
    f.render_widget(conf_chart, bottom[1]);
}

// ── Findings Tab ────────────────────────────────────────────────────────

fn render_findings(f: &mut Frame, area: Rect, state: &mut DashboardState) {
    let main = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(8)])
        .split(area);

    // Filter bar
    render_filter_bar(f, main[0], state);

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(main[1]);

    // Left: Finding list (filtered)
    let filtered = state.filtered_findings();
    let items: Vec<ListItem> = filtered
        .iter()
        .map(|(i, finding)| {
            let sev_color = severity_color(finding.severity);
            let icon = severity_icon(finding.severity);
            let selected = *i == state.selected_finding;

            let line = Line::from(vec![
                Span::styled(format!(" {} ", icon), Style::default().fg(sev_color)),
                Span::styled(format!("{:<8}", finding.id), Style::default().fg(C_ACCENT)),
                Span::styled(
                    truncate_str(&finding.vuln_type, 25),
                    Style::default()
                        .fg(if selected { Color::White } else { C_TEXT })
                        .add_modifier(if selected { Modifier::BOLD } else { Modifier::empty() }),
                ),
            ]);

            let style = if selected {
                Style::default().bg(C_HIGHLIGHT)
            } else {
                Style::default().bg(C_BG)
            };
            ListItem::new(line).style(style)
        })
        .collect();

    let list_title = format!(" {}/{} findings ", filtered.len(), state.findings.len());
    let list = List::new(items)
        .block(panel(&list_title, C_ACCENT))
        .highlight_style(Style::default().bg(C_HIGHLIGHT));
    f.render_stateful_widget(list, cols[0], &mut state.finding_list_state);

    // Right: Detail panel with scroll
    if let Some(finding) = state.findings.get(state.selected_finding) {
        let sev_color = severity_color(finding.severity);
        let w = (cols[1].width as usize).saturating_sub(4);
        let lines = build_detail_lines(finding, w);

        // Scrollbar
        let content_len = lines.len() as u16;
        let view_height = cols[1].height.saturating_sub(2);
        let max_scroll = content_len.saturating_sub(view_height);
        if state.detail_scroll > max_scroll {
            state.detail_scroll = max_scroll;
        }

        let detail_title = format!(" {} | d/u scroll | Enter popup ", finding.id);
        let detail = Paragraph::new(lines)
            .block(panel(&detail_title, sev_color))
            .scroll((state.detail_scroll, 0))
            .wrap(Wrap { trim: false });
        f.render_widget(detail, cols[1]);

        // Scrollbar widget
        if content_len > view_height {
            let mut scrollbar_state = ScrollbarState::new(max_scroll as usize)
                .position(state.detail_scroll as usize);
            f.render_stateful_widget(
                Scrollbar::new(ScrollbarOrientation::VerticalRight)
                    .style(Style::default().fg(C_DIM)),
                cols[1],
                &mut scrollbar_state,
            );
        }
    } else {
        f.render_widget(
            Paragraph::new("No findings").style(Style::default().fg(C_DIM)).block(panel("DETAIL", C_BORDER)),
            cols[1],
        );
    }
}

fn render_filter_bar(f: &mut Frame, area: Rect, state: &DashboardState) {
    let labels = ["[c]rit", "[h]igh", "[m]ed", "[l]ow", "[i]nfo"];
    let colors = [C_RED, C_ORANGE, C_BLUE, C_SLATE, C_DIM];

    let mut spans = vec![Span::styled(" Filter: ", Style::default().fg(C_MUTED))];
    for (i, (label, color)) in labels.iter().zip(colors.iter()).enumerate() {
        let on = state.sev_filter[i];
        let style = if on {
            Style::default().fg(C_BG).bg(*color).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(C_DIM).add_modifier(Modifier::DIM)
        };
        spans.push(Span::styled(format!(" {} ", label), style));
        spans.push(Span::styled(" ", Style::default()));
    }

    let count = state.filtered_findings().len();
    spans.push(Span::styled(
        format!("  showing {}/{}", count, state.findings.len()),
        Style::default().fg(C_MUTED),
    ));

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));
    f.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

fn build_detail_lines<'a>(
    finding: &'a program_analyzer::VulnerabilityFinding,
    w: usize,
) -> Vec<Line<'a>> {
    let sev_color = severity_color(finding.severity);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(
                format!(" {} ", severity_label(finding.severity)),
                Style::default().fg(C_BG).bg(sev_color).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!(" {} ", finding.id), Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD)),
            Span::styled(
                format!(" {}% confidence ", finding.confidence),
                Style::default().fg(confidence_color(finding.confidence)),
            ),
        ]),
        Line::from(""),
        Line::from(vec![
            Span::styled(&finding.vuln_type, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(""),
    ];

    // Metadata
    lines.push(Line::from(vec![
        Span::styled("File:     ", Style::default().fg(C_MUTED)),
        Span::styled(finding.location.as_str(), Style::default().fg(C_TEXT)),
    ]));
    if !finding.function_name.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("Function: ", Style::default().fg(C_MUTED)),
            Span::styled(format!("fn {}", finding.function_name), Style::default().fg(C_PURPLE)),
        ]));
    }
    if finding.line_number > 0 {
        lines.push(Line::from(vec![
            Span::styled("Line:     ", Style::default().fg(C_MUTED)),
            Span::styled(finding.line_number.to_string(), Style::default().fg(C_YELLOW)),
        ]));
    }
    if let Some(ref cwe) = finding.cwe {
        lines.push(Line::from(vec![
            Span::styled("CWE:      ", Style::default().fg(C_MUTED)),
            Span::styled(cwe.as_str(), Style::default().fg(C_ACCENT)),
        ]));
    }

    // Description
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "--- Description ---",
        Style::default().fg(C_BORDER).add_modifier(Modifier::BOLD),
    )));
    for chunk in word_wrap(&finding.description, w) {
        lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_TEXT))));
    }

    // Code
    if !finding.vulnerable_code.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "--- Vulnerable Code ---",
            Style::default().fg(C_ORANGE).add_modifier(Modifier::BOLD),
        )));
        for code_line in finding.vulnerable_code.lines().take(15) {
            lines.push(Line::from(Span::styled(
                format!("  {}", code_line),
                Style::default().fg(C_GREEN),
            )));
        }
    }

    // Attack scenario
    if !finding.attack_scenario.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "--- Attack Scenario ---",
            Style::default().fg(C_RED).add_modifier(Modifier::BOLD),
        )));
        for chunk in word_wrap(&finding.attack_scenario, w) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_MUTED))));
        }
    }

    // Real-world incident
    if let Some(ref incident) = finding.real_world_incident {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled("Incident: ", Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled(&incident.project, Style::default().fg(C_YELLOW)),
            Span::styled(format!(" -- {} ({})", incident.loss, incident.date), Style::default().fg(C_RED)),
        ]));
    }

    // Fix
    if !finding.secure_fix.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::from(Span::styled(
            "--- Recommended Fix ---",
            Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD),
        )));
        for chunk in word_wrap(&finding.secure_fix, w) {
            lines.push(Line::from(Span::styled(chunk, Style::default().fg(C_GREEN))));
        }
    }

    lines
}

// ── Engines Tab ─────────────────────────────────────────────────────────

fn render_engines(f: &mut Frame, area: Rect, state: &DashboardState) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(7)])
        .split(area);

    // Phase timeline bars - show all 10 grouped phases
    let mut phase_lines: Vec<Line> = Vec::new();
    phase_lines.push(Line::from(""));

    for (i, (color, name, desc)) in PHASES.iter().enumerate() {
        let count = state.phase_counts[i];
        let bar_len = count.min(20);
        let bar: String = "█".repeat(bar_len);
        let empty: String = "░".repeat(20 - bar_len);

        let status = if count > 0 {
            Span::styled(format!("{:>3} found", count), Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
        } else {
            Span::styled("  clean", Style::default().fg(C_GREEN))
        };

        // Animated tick indicator
        let tick = if (state.tick_count as usize + i) % 8 < 4 { ">" } else { " " };

        phase_lines.push(Line::from(vec![
            Span::styled(format!("  P{:>2} ", i + 1), Style::default().fg(C_DIM)),
            Span::styled(format!("{:<9}", name), Style::default().fg(*color).add_modifier(Modifier::BOLD)),
            Span::styled(bar, Style::default().fg(*color)),
            Span::styled(empty, Style::default().fg(C_DIM)),
            Span::styled(" ", Style::default()),
            status,
            Span::styled(format!("  {}", desc), Style::default().fg(C_DIM)),
            Span::styled(tick, Style::default().fg(*color)),
        ]));
    }

    f.render_widget(
        Paragraph::new(phase_lines).block(panel("ANALYSIS PHASES", C_ACCENT)),
        rows[0],
    );

    // Summary bar
    let total: usize = state.phase_counts.iter().sum();
    let active_phases = state.phase_counts.iter().filter(|&&c| c > 0).count();
    let (c, _h, _m, _l) = state.severity_counts();

    let summary = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  Total: ", Style::default().fg(C_MUTED)),
            Span::styled(
                total.to_string(),
                Style::default().fg(if total == 0 { C_GREEN } else { C_RED }).add_modifier(Modifier::BOLD),
            ),
            Span::styled(format!("  across {} phases", active_phases), Style::default().fg(C_DIM)),
            Span::styled("    Time: ", Style::default().fg(C_MUTED)),
            Span::styled(format!("{:.2}s", state.scan_duration.as_secs_f64()), Style::default().fg(C_ACCENT)),
            Span::styled(format!("  ({:.0}ms/phase)", state.scan_duration.as_millis() as f64 / 20.0), Style::default().fg(C_DIM)),
            Span::styled("    Verdict: ", Style::default().fg(C_MUTED)),
            if c == 0 {
                Span::styled("PASS", Style::default().fg(C_GREEN).add_modifier(Modifier::BOLD))
            } else {
                Span::styled("BLOCKED", Style::default().fg(C_RED).add_modifier(Modifier::BOLD))
            },
        ]),
    ];
    f.render_widget(Paragraph::new(summary).block(panel("PIPELINE", C_BLUE)), rows[1]);
}

// ── Fix Queue Tab ───────────────────────────────────────────────────────

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

            let fix_preview = truncate_str(&finding.secure_fix, 35);

            let line = Line::from(vec![
                Span::styled(format!(" #{:<2} ", i + 1), Style::default().fg(C_MUTED)),
                Span::styled(
                    format!("[{}] ", priority),
                    Style::default().fg(sev_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!("{:<8}", finding.id), Style::default().fg(C_ACCENT)),
                Span::styled(" | ", Style::default().fg(C_BORDER)),
                Span::styled(truncate_str(&finding.vuln_type, 22), Style::default().fg(C_TEXT)),
                Span::styled(" | ", Style::default().fg(C_BORDER)),
                Span::styled(fix_preview, Style::default().fg(C_GREEN)),
            ]);

            ListItem::new(line).style(Style::default().bg(C_BG))
        })
        .collect();

    let title = format!(" FIX QUEUE -- {} items by priority ", sorted.len());
    let list = List::new(items).block(panel(&title, C_GREEN));
    f.render_widget(list, area);
}

// ── Help Tab ────────────────────────────────────────────────────────────

fn render_help(f: &mut Frame, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  SHANON SECURITY CONSOLE -- KEYBOARD SHORTCUTS",
            Style::default().fg(C_ACCENT).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        help_line("Tab / Shift+Tab", "Switch between tabs"),
        help_line("1-5", "Jump to specific tab"),
        help_line("j / k", "Navigate findings"),
        help_line("Enter", "Toggle detail popup"),
        help_line("d / u", "Scroll detail down/up"),
        help_line("c h m l i", "Toggle severity filters"),
        help_line("?", "Show this help"),
        help_line("q / Esc", "Quit dashboard"),
        Line::from(""),
        Line::from(Span::styled("  ANALYSIS PHASES", Style::default().fg(C_PURPLE).add_modifier(Modifier::BOLD))),
        Line::from(""),
    ];

    let mut all_lines = lines;
    for (color, name, desc) in &PHASES {
        all_lines.push(Line::from(vec![
            Span::styled(format!("  {:<12}", name), Style::default().fg(*color).add_modifier(Modifier::BOLD)),
            Span::styled(*desc, Style::default().fg(C_MUTED)),
        ]));
    }

    all_lines.push(Line::from(""));
    all_lines.push(Line::from(Span::styled(
        "  Built with ratatui | 20 phases | 72+ detectors | Z3 formal verification",
        Style::default().fg(C_DIM),
    )));

    f.render_widget(Paragraph::new(all_lines).block(panel("HELP", C_ACCENT)), area);
}

// ── Footer ──────────────────────────────────────────────────────────────

fn render_footer(f: &mut Frame, area: Rect, state: &DashboardState) {
    let (c, _h, _m, _l) = state.severity_counts();
    let verdict = if c == 0 {
        Span::styled(" PASS ", Style::default().fg(C_BG).bg(C_GREEN).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" BLOCKED ", Style::default().fg(Color::White).bg(C_RED).add_modifier(Modifier::BOLD))
    };

    let elapsed = format!("{:.1}s", state.scan_duration.as_secs_f64());

    let footer = Line::from(vec![
        Span::styled(" ", Style::default()),
        verdict,
        Span::styled(format!("  {} findings | {} | ", state.findings.len(), elapsed), Style::default().fg(C_DIM)),
        Span::styled("q:quit  Tab:switch  j/k:nav  Enter:detail  c/h/m/l:filter", Style::default().fg(C_MUTED)),
    ]);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(C_BORDER))
        .style(Style::default().bg(C_BG));
    f.render_widget(Paragraph::new(footer).block(block), area);
}

// ── Detail Popup ────────────────────────────────────────────────────────

fn render_detail_popup(f: &mut Frame, state: &DashboardState) {
    let popup_area = centered_rect(82, 82, f.area());
    f.render_widget(Clear, popup_area);

    if let Some(finding) = state.findings.get(state.selected_finding) {
        let sev_color = severity_color(finding.severity);
        let w = (popup_area.width as usize).saturating_sub(4);
        let lines = build_detail_lines(finding, w);

        let block = Block::default()
            .title(format!(" {} -- {} ", finding.id, severity_label(finding.severity)))
            .borders(Borders::ALL)
            .border_type(BorderType::Thick)
            .border_style(Style::default().fg(sev_color))
            .style(Style::default().bg(C_BG));

        f.render_widget(
            Paragraph::new(lines)
                .block(block)
                .scroll((state.detail_scroll, 0))
                .wrap(Wrap { trim: false }),
            popup_area,
        );
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn panel(title: &str, color: Color) -> Block<'_> {
    Block::default()
        .title(format!(" {} ", title))
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
        5 => "!!",
        4 => "!.",
        3 => "..",
        _ => "--",
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

fn help_line<'a>(key: &'a str, desc: &'a str) -> Line<'a> {
    Line::from(vec![
        Span::styled(format!("  {:<20}", key), Style::default().fg(C_YELLOW).add_modifier(Modifier::BOLD)),
        Span::styled(desc, Style::default().fg(C_TEXT)),
    ])
}

fn truncate_str(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}..", &s[..max.saturating_sub(2)])
    }
}

fn truncate_path(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    if let Some(last) = s.rsplit('/').next() {
        if last.len() <= max {
            return format!("../{}", last);
        }
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
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let v = Layout::default()
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
        .split(v[1])[1]
}

fn compute_category_counts(findings: &[program_analyzer::VulnerabilityFinding]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for f in findings {
        *map.entry(f.category.clone()).or_insert(0) += 1;
    }
    map
}

fn compute_cwe_counts(findings: &[program_analyzer::VulnerabilityFinding]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for f in findings {
        if let Some(ref cwe) = f.cwe {
            *map.entry(cwe.clone()).or_insert(0) += 1;
        }
    }
    map
}

fn compute_phase_counts(findings: &[program_analyzer::VulnerabilityFinding]) -> [usize; 10] {
    let mut counts = [0usize; 10];
    for f in findings {
        let id = &f.id;
        let idx = if id.starts_with("SOL-DEEP") {
            1
        } else if id.starts_with("SOL-TAINT") || id == "SOL-092" {
            2
        } else if id.starts_with("SOL-CFG") {
            3
        } else if id.starts_with("SOL-ABS") {
            4
        } else if id.starts_with("SOL-ALIAS") {
            5
        } else if id.starts_with("SOL-07") {
            6 // Sec3
        } else if id.starts_with("SOL-08") {
            7 // Anchor
        } else if id.starts_with("SOL-09") {
            8 // Dataflow/experimental
        } else if id.starts_with("SOL-FV") || id.starts_with("SOL-SYM") {
            9 // Formal verification
        } else {
            0 // Pattern scanner
        };
        counts[idx] += 1;
    }
    counts
}
