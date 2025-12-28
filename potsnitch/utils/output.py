"""Output formatting utilities."""

import csv
import io
import json
from typing import Union

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from potsnitch.core.result import DetectionResult, ScanReport, Confidence


console = Console()


def format_json(data: Union[ScanReport, DetectionResult, list]) -> str:
    """Format results as JSON.

    Args:
        data: ScanReport, DetectionResult, or list of results

    Returns:
        JSON string
    """
    if isinstance(data, list):
        return json.dumps([d.to_dict() for d in data], indent=2)
    return json.dumps(data.to_dict(), indent=2)


def format_csv(data: Union[ScanReport, list[DetectionResult]]) -> str:
    """Format results as CSV.

    Args:
        data: ScanReport or list of DetectionResults

    Returns:
        CSV string
    """
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "target",
        "port",
        "honeypot_type",
        "is_honeypot",
        "confidence",
        "confidence_score",
        "indicators",
        "scan_time",
    ])

    if isinstance(data, ScanReport):
        results = data.detections
    else:
        results = data

    for result in results:
        indicators = "; ".join([i.description for i in result.indicators])
        writer.writerow([
            result.target,
            result.port,
            result.honeypot_type or "",
            result.is_honeypot,
            result.confidence.value,
            result.confidence.score,
            indicators,
            result.scan_time.isoformat(),
        ])

    return output.getvalue()


def format_table(data: Union[ScanReport, list[DetectionResult]]) -> None:
    """Print results as a rich table.

    Args:
        data: ScanReport or list of DetectionResults
    """
    if isinstance(data, ScanReport):
        results = data.detections
        target = data.target
    else:
        results = data
        target = results[0].target if results else "Unknown"

    # Filter to honeypots only for main table
    honeypots = [r for r in results if r.is_honeypot]

    if not honeypots:
        console.print(f"\n[green]No honeypots detected on {target}[/green]\n")
        return

    # Create main results table
    table = Table(title=f"Honeypot Detection Results: {target}")
    table.add_column("Port", style="cyan", justify="right")
    table.add_column("Type", style="magenta")
    table.add_column("Confidence", justify="center")
    table.add_column("Indicators", style="dim")

    for result in honeypots:
        # Color confidence
        conf_color = {
            Confidence.LOW: "yellow",
            Confidence.MEDIUM: "orange3",
            Confidence.HIGH: "red",
            Confidence.DEFINITE: "bold red",
        }.get(result.confidence, "white")

        conf_text = Text(f"{result.confidence.value} ({result.confidence.score:.0%})")
        conf_text.stylize(conf_color)

        indicators = "\n".join([f"- {i.description}" for i in result.indicators[:3]])
        if len(result.indicators) > 3:
            indicators += f"\n... +{len(result.indicators) - 3} more"

        table.add_row(
            str(result.port),
            result.honeypot_type or "Unknown",
            conf_text,
            indicators,
        )

    console.print()
    console.print(table)
    console.print()


def print_validation_report(
    target: str,
    honeypot_type: str,
    result: DetectionResult,
    recommendations: list[str],
) -> None:
    """Print detailed validation report for defensive testing.

    Args:
        target: Target address
        honeypot_type: Type of honeypot being validated
        result: Detection result
        recommendations: List of remediation recommendations
    """
    title = f"{honeypot_type.title()} Validation Report for {target}"

    lines = []
    for indicator in result.indicators:
        if indicator.severity == Confidence.DEFINITE:
            status = "[bold red][FAIL][/bold red]"
        elif indicator.severity == Confidence.HIGH:
            status = "[red][FAIL][/red]"
        elif indicator.severity == Confidence.MEDIUM:
            status = "[yellow][WARN][/yellow]"
        else:
            status = "[green][PASS][/green]"

        lines.append(f"{status} {indicator.description}")
        if indicator.details:
            lines.append(f"      [dim]{indicator.details}[/dim]")

    content = "\n".join(lines)

    if recommendations:
        content += "\n\n[bold]Recommendations:[/bold]\n"
        for rec in recommendations:
            content += f"  - {rec}\n"

    panel = Panel(content, title=title, border_style="blue")
    console.print()
    console.print(panel)
    console.print()
