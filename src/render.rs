use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use humansize::{BINARY, format_size};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::Constraint,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Row, Table},
};
use std::time::Duration;
use std::{io, net::IpAddr};

use crate::model::{HostStats, StatsMap};

pub fn run_ui(stats: StatsMap) -> io::Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    loop {
        // Handle quit key
        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if key.code == KeyCode::Char('q') {
                    break;
                }
            }
        }

        // Snapshot + sort by total bytes descending
        let mut rows: Vec<(IpAddr, HostStats)> = stats
            .iter()
            .map(|entry| (*entry.key(), entry.value().clone()))
            .collect();
        rows.sort_by(|a, b| b.1.total().cmp(&a.1.total()));

        terminal.draw(|frame| {
            let area = frame.area();

            let table_rows: Vec<Row> = rows
                .iter()
                .take(30)
                .map(|(ip, s)| {
                    let label = s.hostname.clone().unwrap_or_else(|| ip.to_string());
                    Row::new(vec![
                        label,
                        ip.to_string(),
                        format_size(s.bytes_sent, BINARY),
                        format_size(s.bytes_received, BINARY),
                        format_size(s.total(), BINARY),
                        s.packets.to_string(),
                    ])
                })
                .collect();

            let widths = [
                Constraint::Percentage(30),
                Constraint::Percentage(20),
                Constraint::Percentage(12),
                Constraint::Percentage(12),
                Constraint::Percentage(14),
                Constraint::Percentage(12),
            ];

            let table = Table::new(table_rows, widths)
                .header(
                    Row::new(vec!["Host", "IP", "Sent", "Received", "Total", "Packets"])
                        .style(Style::default().add_modifier(Modifier::BOLD)),
                )
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(" Live Traffic (press 'q' to quit) "),
                )
                .row_highlight_style(Style::default().fg(Color::Yellow));

            frame.render_widget(table, area);
        })?;
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    Ok(())
}
