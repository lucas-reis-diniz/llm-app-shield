# llmapp_shield/cli.py
"""
LLMAppShield — CLI entry point.

Provides the `llmapp-shield` command with subcommands:
  - scan: Analyze source files for LLM security vulnerabilities
  - rules: List available detection rules
  - version: Show version info
"""

from __future__ import annotations

import sys
import time
from pathlib import Path
from typing import Optional

import typer
from rich import print as rprint
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from llmapp_shield import __version__
from llmapp_shield.scanner import Scanner, ScanConfig
from llmapp_shield.report.renderer import ReportRenderer

app = typer.Typer(
    name="llmapp-shield",
    help="🛡️  AI Security Scanner for LLM Applications — OWASP LLM Top 10",
    add_completion=False,
    rich_markup_mode="rich",
)

console = Console()


def _print_banner() -> None:
    """Print the LLMAppShield ASCII banner."""
    banner = Text()
    banner.append("🛡️  LLMAppShield", style="bold cyan")
    banner.append(f" v{__version__}", style="dim")
    banner.append("  |  ", style="dim")
    banner.append("OWASP LLM Top 10 — 2025 Edition", style="bold yellow")

    console.print(
        Panel(
            banner,
            border_style="cyan",
            padding=(0, 2),
        )
    )


@app.command()
def scan(
    target: Path = typer.Argument(
        ...,
        help="File or directory to scan",
        show_default=False,
    ),
    format: str = typer.Option(
        "terminal",
        "--format", "-f",
        help="Output format: terminal, html, json, all",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output file path (for html/json formats)",
    ),
    severity: str = typer.Option(
        "low",
        "--severity", "-s",
        help="Minimum severity to report: critical, high, medium, low",
    ),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        help="Exit with code 1 if findings at this severity or above exist",
    ),
    llm_judge: bool = typer.Option(
        False,
        "--llm-judge",
        help="Enable LLM-as-Judge for semantic analysis (requires Ollama/Groq)",
    ),
    llm_provider: str = typer.Option(
        "ollama",
        "--llm-provider",
        help="LLM provider for judge mode: ollama, groq",
    ),
    llm_model: str = typer.Option(
        "llama3.2",
        "--llm-model",
        help="Model name for LLM judge",
    ),
    llm_endpoint: str = typer.Option(
        "http://localhost:11434",
        "--llm-endpoint",
        help="Endpoint URL for Ollama",
    ),
    ignore_file: Optional[Path] = typer.Option(
        None,
        "--ignore-file",
        help="Path to .llmappignore file (auto-detected if not specified)",
    ),
    language: str = typer.Option(
        "en-US",
        "--lang",
        help="Report language: en-US, pt-BR",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Show detailed progress and debug information",
    ),
    no_banner: bool = typer.Option(
        False,
        "--no-banner",
        help="Suppress banner (useful for CI)",
    ),
) -> None:
    """
    🔍 Scan a file or directory for LLM security vulnerabilities.

    Examples:

      llmapp-shield scan .

      llmapp-shield scan app.py --format html --output report.html

      llmapp-shield scan . --fail-on high --format json
    """
    if not no_banner:
        _print_banner()

    # Validate target path
    if not target.exists():
        console.print(f"[red]❌ Error: Path not found: {target}[/red]")
        raise typer.Exit(code=2)

    # Validate format
    valid_formats = {"terminal", "html", "json", "all"}
    if format not in valid_formats:
        console.print(f"[red]❌ Invalid format '{format}'. Choose: {', '.join(valid_formats)}[/red]")
        raise typer.Exit(code=2)

    # Validate severity
    valid_severities = {"critical", "high", "medium", "low"}
    if severity.lower() not in valid_severities:
        console.print(f"[red]❌ Invalid severity. Choose: {', '.join(valid_severities)}[/red]")
        raise typer.Exit(code=2)

    # Build scan config
    config = ScanConfig(
        target=target,
        min_severity=severity.lower(),
        fail_on=fail_on.lower() if fail_on else None,
        llm_judge=llm_judge,
        llm_provider=llm_provider,
        llm_model=llm_model,
        llm_endpoint=llm_endpoint,
        ignore_file=ignore_file,
        report_language=language,
        verbose=verbose,
        output_format=format,
        output_path=output,
    )

    # Run scanner
    start_time = time.time()
    scanner = Scanner(config, console=console)

    try:
        result = scanner.run()
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Scan interrupted by user[/yellow]")
        raise typer.Exit(code=130)
    except Exception as e:
        console.print(f"[red]❌ Unexpected error during scan: {e}[/red]")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)

    elapsed = time.time() - start_time

    # Render report
    renderer = ReportRenderer(config, console=console)
    renderer.render(result, elapsed_seconds=elapsed)

    # Check fail_on threshold
    if fail_on and result.has_severity(fail_on.lower()):
        console.print(
            f"\n[red bold]❌ FAILED: Found findings at '{fail_on.upper()}' severity or above.[/red bold]"
        )
        raise typer.Exit(code=1)

    if result.total_findings == 0:
        console.print("\n[green bold]✅ No vulnerabilities found! Your LLM app looks clean.[/green bold]")
    else:
        console.print(f"\n[yellow]⚠️  Scan complete: {result.total_findings} finding(s) in {elapsed:.1f}s[/yellow]")


@app.command()
def rules(
    category: Optional[str] = typer.Option(
        None,
        "--category", "-c",
        help="Filter by category (e.g., prompt_injection, data_leak)",
    ),
    format: str = typer.Option(
        "table",
        "--format", "-f",
        help="Output format: table, json",
    ),
) -> None:
    """
    📋 List all available detection rules.
    """
    from llmapp_shield.rules.loader import RuleLoader

    _print_banner()

    loader = RuleLoader()
    all_rules = loader.load_all()

    if category:
        all_rules = [r for r in all_rules if r.category == category]

    if format == "json":
        import json
        rprint(json.dumps([r.model_dump() for r in all_rules], indent=2))
        return

    table = Table(
        title=f"🛡️  Available Rules ({len(all_rules)} total)",
        border_style="cyan",
        show_lines=True,
    )
    table.add_column("ID", style="cyan bold", width=15)
    table.add_column("Name", style="white", width=35)
    table.add_column("Category", style="blue", width=20)
    table.add_column("Severity", width=10)
    table.add_column("Language", width=12)

    severity_colors = {
        "critical": "[red bold]CRITICAL[/red bold]",
        "high": "[orange1]HIGH[/orange1]",
        "medium": "[yellow]MEDIUM[/yellow]",
        "low": "[blue]LOW[/blue]",
    }

    for rule in sorted(all_rules, key=lambda r: r.id):
        table.add_row(
            rule.id,
            rule.name,
            rule.category,
            severity_colors.get(rule.severity, rule.severity),
            rule.language or "any",
        )

    console.print(table)


@app.command()
def version() -> None:
    """
    ℹ️  Show version and system information.
    """
    import platform

    table = Table(show_header=False, border_style="cyan", padding=(0, 2))
    table.add_column("Key", style="cyan bold")
    table.add_column("Value", style="white")

    table.add_row("LLMAppShield", f"v{__version__}")
    table.add_row("Python", platform.python_version())
    table.add_row("Platform", platform.system())
    table.add_row("OWASP LLM Top 10", "2025 Edition")
    table.add_row("License", "MIT")
    table.add_row("Repository", "https://github.com/llmappshield/llmapp-shield")

    console.print(table)


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
