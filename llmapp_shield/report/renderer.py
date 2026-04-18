# llmapp_shield/report/renderer.py
"""
Report Renderer — Generates rich terminal output, HTML reports, and JSON exports.

Supports:
- Terminal: Rich tables, syntax highlighting, colored severity
- HTML: Interactive report with filtering, charts, code snippets
- JSON: Machine-readable output for CI/CD pipelines
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, TYPE_CHECKING

from jinja2 import Environment, BaseLoader
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text

from llmapp_shield.models import Finding, ScanResult, Severity

if TYPE_CHECKING:
    from llmapp_shield.scanner import ScanConfig


SEVERITY_COLORS = {
    "critical": "bold red",
    "high": "bold orange1",
    "medium": "bold yellow",
    "low": "bold blue",
    "info": "dim",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🔵",
    "info": "⚪",
}


class ReportRenderer:
    """
    Renders scan results in multiple formats.

    Supports terminal (Rich), HTML (interactive), and JSON output.
    Respects the configured output format and language (en-US / pt-BR).
    """

    def __init__(self, config: "ScanConfig", console: Optional[Console] = None) -> None:
        self.config = config
        self.console = console or Console()

    def render(self, result: ScanResult, elapsed_seconds: float = 0.0) -> None:
        """Render the report in all configured formats."""
        fmt = self.config.output_format.lower()

        if fmt in ("terminal", "all"):
            self._render_terminal(result, elapsed_seconds)

        if fmt in ("html", "all"):
            output_path = self.config.output_path or Path("llmshield-report.html")
            self._render_html(result, output_path)
            self.console.print(f"[green]📄 HTML Report: {output_path}[/green]")

        if fmt in ("json", "all"):
            json_path = self.config.output_path or Path("llmshield-report.json")
            if fmt == "all":
                json_path = json_path.with_suffix("").with_suffix(".json")
            self._render_json(result, json_path)
            self.console.print(f"[green]📦 JSON Report: {json_path}[/green]")

    # ─── Terminal Renderer ──────────────────────────────────────────────────────

    def _render_terminal(self, result: ScanResult, elapsed: float) -> None:
        """Render rich terminal output."""
        self.console.print()

        # Summary panel
        self._render_summary(result, elapsed)
        self.console.print()

        if result.total_findings == 0:
            return

        # Findings by severity (Critical → Low)
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            findings = result.by_severity.get(severity.value, [])
            if findings:
                self._render_severity_section(severity, findings)

        # File summary table
        self._render_file_table(result)

    def _render_summary(self, result: ScanResult, elapsed: float) -> None:
        """Render scan summary with counts by severity."""
        is_pt = self.config.report_language == "pt-BR"

        # Stats grid
        stats = Table.grid(expand=True)
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")
        stats.add_column(justify="center")

        def _stat(emoji: str, count: int, label: str, color: str) -> Text:
            t = Text()
            t.append(f"\n{emoji} ", style="bold")
            t.append(str(count), style=f"bold {color}")
            t.append(f"\n{label}\n", style="dim")
            return t

        stats.add_row(
            _stat("🔴", result.critical_count, "CRITICAL", "red"),
            _stat("🟠", result.high_count, "HIGH", "orange1"),
            _stat("🟡", result.medium_count, "MEDIUM", "yellow"),
            _stat("🔵", result.low_count, "LOW", "blue"),
            _stat("📁", result.scanned_files, "FILES" if not is_pt else "ARQUIVOS", "cyan"),
        )

        title = "🛡️  Resultados do Scan" if is_pt else "🛡️  Scan Results"
        subtitle = f"{'Concluído em' if is_pt else 'Completed in'} {elapsed:.1f}s — {result.total_findings} {'achados' if is_pt else 'findings'}"

        self.console.print(Panel(
            stats,
            title=f"[bold cyan]{title}[/bold cyan]",
            subtitle=f"[dim]{subtitle}[/dim]",
            border_style="cyan",
            padding=(0, 1),
        ))

    def _render_severity_section(self, severity: Severity, findings: list[Finding]) -> None:
        """Render all findings for a given severity level."""
        emoji = SEVERITY_EMOJI[severity.value]
        color = SEVERITY_COLORS[severity.value]

        self.console.print(Rule(
            f"{emoji} [{color}]{severity.value.upper()}[/{color}] — {len(findings)} finding(s)",
            style=color.split()[-1],
        ))
        self.console.print()

        for finding in findings:
            self._render_finding(finding)

    def _render_finding(self, finding: Finding) -> None:
        """Render a single finding with details."""
        is_pt = self.config.report_language == "pt-BR"
        color = SEVERITY_COLORS[finding.severity.value]
        emoji = SEVERITY_EMOJI[finding.severity.value]

        # Header
        title = Text()
        title.append(f"{emoji} [{finding.rule_id}] ", style=color)
        title.append(finding.title, style="bold white")

        # Location
        loc = Text()
        loc.append("📍 ", style="dim")
        loc.append(str(finding.file_path), style="cyan")
        loc.append(f":{finding.line}", style="dim cyan")
        if finding.owasp:
            loc.append(f"  |  {finding.owasp.id}: {finding.owasp.name}", style="dim yellow")
        loc.append(f"  |  Confidence: {finding.confidence:.0%}", style="dim")

        # Description
        desc = finding.description_pt if is_pt and finding.description_pt else finding.description

        # Code snippet
        code_panel = None
        if finding.code_snippet:
            lang = _guess_syntax_lang(finding.file_path)
            code_panel = Syntax(
                finding.code_snippet,
                lang,
                theme="monokai",
                line_numbers=True,
                start_line=max(1, finding.line - 2),
                highlight_lines={finding.line},
            )

        # Recommendation
        rec = finding.recommendation_pt if is_pt and finding.recommendation_pt else finding.recommendation

        # Build panel content
        content = Text()
        content.append("\n")
        content.append(loc)
        content.append("\n\n")
        content.append("📋 ", style="dim")
        content.append(desc, style="white")
        if rec:
            content.append("\n\n")
            content.append("💡 Fix: ", style="bold green")
            content.append(rec, style="green")

        self.console.print(Panel(
            content,
            title=title,
            border_style=color.split()[-1],
            padding=(0, 1),
        ))

        if code_panel:
            self.console.print(Panel(code_panel, border_style="dim", padding=(0, 1)))

        if finding.fix_example:
            lang = _guess_syntax_lang(finding.file_path)
            self.console.print(Panel(
                Syntax(finding.fix_example.strip(), lang, theme="monokai"),
                title="[bold green]✅ Fix Example[/bold green]",
                border_style="green",
                padding=(0, 1),
            ))

        self.console.print()

    def _render_file_table(self, result: ScanResult) -> None:
        """Render a summary table of findings per file."""
        table = Table(
            title="📁 Findings by File",
            border_style="dim",
            show_lines=True,
            box=box.SIMPLE_HEAVY,
        )
        table.add_column("File", style="cyan", no_wrap=True)
        table.add_column("🔴 Critical", justify="center")
        table.add_column("🟠 High", justify="center")
        table.add_column("🟡 Medium", justify="center")
        table.add_column("🔵 Low", justify="center")
        table.add_column("Total", justify="center", style="bold")

        for file_path, findings in sorted(result.by_file.items()):
            by_sev = {s.value: 0 for s in Severity}
            for f in findings:
                by_sev[f.severity.value] += 1

            table.add_row(
                file_path,
                str(by_sev["critical"]) if by_sev["critical"] else "—",
                str(by_sev["high"]) if by_sev["high"] else "—",
                str(by_sev["medium"]) if by_sev["medium"] else "—",
                str(by_sev["low"]) if by_sev["low"] else "—",
                str(len(findings)),
            )

        self.console.print(table)

    # ─── JSON Renderer ──────────────────────────────────────────────────────────

    def _render_json(self, result: ScanResult, output_path: Path) -> None:
        """Render findings as machine-readable JSON."""
        target_str = str(self.config.target) if self.config else "unknown"
        data = {
            "meta": {
                "tool": "LLMAppShield",
                "version": "0.1.0",
                "owasp_version": "LLM Top 10 2025",
                "scanned_at": result.scanned_at.isoformat(),
                "target": target_str,
                "scanned_files": result.scanned_files,
            },
            "summary": {
                "total": result.total_findings,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
            },
            "findings": [f.to_dict() for f in result.sorted_findings()],
        }

        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, indent=2, default=str)

    # ─── HTML Renderer ──────────────────────────────────────────────────────────

    def _render_html(self, result: ScanResult, output_path: Path) -> None:
        """Render an interactive HTML report."""
        env = Environment(loader=BaseLoader(), autoescape=True)
        template = env.from_string(_HTML_TEMPLATE)

        target_str = str(self.config.target) if self.config else "unknown"
        html = template.render(
            result=result,
            findings=result.sorted_findings(),
            scanned_at=result.scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
            target=target_str,
            severity_colors={
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "info": "#6b7280",
            },
            severity_emoji=SEVERITY_EMOJI,
        )

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(html, encoding="utf-8")


def _guess_syntax_lang(file_path: Path) -> str:
    ext_map = {".py": "python", ".ts": "typescript", ".tsx": "tsx",
               ".js": "javascript", ".jsx": "jsx"}
    return ext_map.get(file_path.suffix.lower(), "text")


# ─── HTML Template ──────────────────────────────────────────────────────────────

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LLMAppShield Security Report</title>
<style>
  :root {
    --bg: #0f1117; --surface: #1a1d2e; --surface2: #252840;
    --border: #2d3158; --text: #e2e8f0; --muted: #94a3b8;
    --accent: #6366f1; --critical: #ef4444; --high: #f97316;
    --medium: #eab308; --low: #3b82f6; --success: #22c55e;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; line-height: 1.6; }
  .navbar { background: var(--surface); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; align-items: center; gap: 1rem; position: sticky; top: 0; z-index: 100; }
  .logo { font-size: 1.4rem; font-weight: 800; background: linear-gradient(135deg, #6366f1, #06b6d4); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
  .badge { padding: 0.2rem 0.6rem; border-radius: 999px; font-size: 0.75rem; font-weight: 600; background: var(--surface2); border: 1px solid var(--border); }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
  .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat-card { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 1.5rem; text-align: center; transition: transform .2s; }
  .stat-card:hover { transform: translateY(-2px); }
  .stat-number { font-size: 2.5rem; font-weight: 800; line-height: 1; }
  .stat-label { color: var(--muted); font-size: 0.8rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .filters { display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .filter-btn { padding: 0.4rem 1rem; border-radius: 999px; border: 1px solid var(--border); background: var(--surface); color: var(--text); cursor: pointer; font-size: 0.85rem; transition: all .2s; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); background: var(--accent); }
  .finding { background: var(--surface); border: 1px solid var(--border); border-radius: 12px; margin-bottom: 1rem; overflow: hidden; transition: box-shadow .2s; }
  .finding:hover { box-shadow: 0 4px 20px rgba(0,0,0,.3); }
  .finding-header { padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem; cursor: pointer; }
  .severity-badge { padding: 0.25rem 0.75rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; text-transform: uppercase; }
  .finding-title { font-weight: 600; flex: 1; }
  .finding-meta { color: var(--muted); font-size: 0.8rem; }
  .finding-body { padding: 0 1.5rem 1.5rem; display: none; }
  .finding.open .finding-body { display: block; }
  .finding-location { background: var(--surface2); border-radius: 8px; padding: 0.75rem 1rem; margin-bottom: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 0.85rem; color: #06b6d4; }
  .code-block { background: #1e1e2e; border-radius: 8px; padding: 1rem; font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; overflow-x: auto; white-space: pre; margin-bottom: 1rem; border: 1px solid var(--border); }
  .desc-section { margin-bottom: 1rem; }
  .desc-label { color: var(--accent); font-size: 0.8rem; font-weight: 600; text-transform: uppercase; margin-bottom: 0.4rem; }
  .fix-box { background: rgba(34, 197, 94, 0.05); border: 1px solid rgba(34, 197, 94, 0.2); border-radius: 8px; padding: 0.75rem 1rem; }
  .owasp-link { color: var(--accent); text-decoration: none; font-size: 0.8rem; }
  .owasp-link:hover { text-decoration: underline; }
  .chevron { transition: transform .2s; }
  .finding.open .chevron { transform: rotate(180deg); }
  footer { text-align: center; color: var(--muted); font-size: 0.8rem; padding: 3rem 0 2rem; border-top: 1px solid var(--border); margin-top: 3rem; }
  @media (max-width: 600px) { .stats-grid { grid-template-columns: repeat(2, 1fr); } }
</style>
</head>
<body>

<nav class="navbar">
  <span class="logo">🛡️ LLMAppShield</span>
  <span class="badge">v0.1.0</span>
  <span class="badge">OWASP LLM Top 10 2025</span>
  <span style="margin-left:auto; color:var(--muted); font-size:0.85rem;">{{ scanned_at }}</span>
</nav>

<div class="container">
  <div style="margin: 2rem 0 1.5rem;">
    <h1 style="font-size:1.8rem; font-weight:800;">Security Report</h1>
    <p style="color:var(--muted); margin-top:0.3rem;">Target: <code style="color:#06b6d4;">{{ target }}</code> — {{ result.scanned_files }} files scanned</p>
  </div>

  <div class="stats-grid">
    <div class="stat-card" style="border-color: #ef444440;">
      <div class="stat-number" style="color:#ef4444;">{{ result.critical_count }}</div>
      <div class="stat-label">🔴 Critical</div>
    </div>
    <div class="stat-card" style="border-color: #f9731640;">
      <div class="stat-number" style="color:#f97316;">{{ result.high_count }}</div>
      <div class="stat-label">🟠 High</div>
    </div>
    <div class="stat-card" style="border-color: #eab30840;">
      <div class="stat-number" style="color:#eab308;">{{ result.medium_count }}</div>
      <div class="stat-label">🟡 Medium</div>
    </div>
    <div class="stat-card" style="border-color: #3b82f640;">
      <div class="stat-number" style="color:#3b82f6;">{{ result.low_count }}</div>
      <div class="stat-label">🔵 Low</div>
    </div>
    <div class="stat-card">
      <div class="stat-number" style="color:#6366f1;">{{ result.total_findings }}</div>
      <div class="stat-label">Total Findings</div>
    </div>
  </div>

  <div class="filters">
    <button class="filter-btn active" onclick="filterFindings('all')">All ({{ result.total_findings }})</button>
    {% if result.critical_count %}<button class="filter-btn" onclick="filterFindings('critical')" style="color:#ef4444; border-color:#ef444440;">🔴 Critical ({{ result.critical_count }})</button>{% endif %}
    {% if result.high_count %}<button class="filter-btn" onclick="filterFindings('high')" style="color:#f97316; border-color:#f9731640;">🟠 High ({{ result.high_count }})</button>{% endif %}
    {% if result.medium_count %}<button class="filter-btn" onclick="filterFindings('medium')" style="color:#eab308; border-color:#eab30840;">🟡 Medium ({{ result.medium_count }})</button>{% endif %}
    {% if result.low_count %}<button class="filter-btn" onclick="filterFindings('low')" style="color:#3b82f6; border-color:#3b82f640;">🔵 Low ({{ result.low_count }})</button>{% endif %}
  </div>

  <div id="findings-list">
  {% for finding in findings %}
  <div class="finding" data-severity="{{ finding.severity.value }}" id="finding-{{ loop.index }}">
    <div class="finding-header" onclick="toggleFinding({{ loop.index }})">
      <span class="severity-badge" style="background: {{ severity_colors[finding.severity.value] }}20; color: {{ severity_colors[finding.severity.value] }}; border: 1px solid {{ severity_colors[finding.severity.value] }}40;">
        {{ severity_emoji[finding.severity.value] }} {{ finding.severity.value.upper() }}
      </span>
      <span class="finding-title">{{ finding.title }}</span>
      <span class="finding-meta">{{ finding.rule_id }}</span>
      <svg class="chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m6 9 6 6 6-6"/></svg>
    </div>
    <div class="finding-body">
      <div class="finding-location">
        📍 {{ finding.file_path }}:{{ finding.line }}
        {% if finding.owasp %} &nbsp;|&nbsp; <a class="owasp-link" href="{{ finding.owasp.url }}" target="_blank">{{ finding.owasp.id }}: {{ finding.owasp.name }}</a>{% endif %}
        &nbsp;|&nbsp; Confidence: {{ "%.0f"|format(finding.confidence * 100) }}%
      </div>
      {% if finding.code_snippet %}
      <div class="code-block">{{ finding.code_snippet }}</div>
      {% endif %}
      <div class="desc-section">
        <div class="desc-label">Description</div>
        <div>{{ finding.description }}</div>
      </div>
      {% if finding.recommendation %}
      <div class="desc-section">
        <div class="desc-label">Recommendation</div>
        <div class="fix-box">💡 {{ finding.recommendation }}</div>
      </div>
      {% endif %}
      {% if finding.fix_example %}
      <div class="desc-section">
        <div class="desc-label">Fix Example</div>
        <div class="code-block">{{ finding.fix_example }}</div>
      </div>
      {% endif %}
      {% if finding.tags %}
      <div style="margin-top:0.75rem; display:flex; gap:0.4rem; flex-wrap:wrap;">
        {% for tag in finding.tags %}<span class="badge">{{ tag }}</span>{% endfor %}
      </div>
      {% endif %}
    </div>
  </div>
  {% else %}
  <div style="text-align:center; padding:4rem; color:var(--muted);">
    <div style="font-size:3rem; margin-bottom:1rem;">✅</div>
    <div style="font-size:1.2rem; font-weight:600;">No vulnerabilities found!</div>
    <div>Your LLM application looks clean.</div>
  </div>
  {% endfor %}
  </div>
</div>

<footer>
  Generated by <strong>LLMAppShield v0.1.0</strong> — OWASP LLM Top 10 2025 —
  <a href="https://github.com/llmappshield/llmapp-shield" style="color:var(--accent);">github.com/llmappshield</a>
  <br>Built with ❤️ in 🇧🇷 Brazil
</footer>

<script>
function toggleFinding(id) {
  const el = document.getElementById('finding-' + id);
  el.classList.toggle('open');
}
function filterFindings(severity) {
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding').forEach(f => {
    if (severity === 'all' || f.dataset.severity === severity) {
      f.style.display = '';
    } else {
      f.style.display = 'none';
    }
  });
}
// Auto-open critical findings
document.querySelectorAll('.finding[data-severity="critical"]').forEach(f => f.classList.add('open'));
</script>
</body>
</html>"""