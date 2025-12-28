"""Command-line interface for PotSnitch."""

import json
import sys

import click
from rich.console import Console

from potsnitch import __version__
from potsnitch.scanner import HoneypotScanner
from potsnitch.utils.output import (
    format_json,
    format_csv,
    format_table,
    print_validation_report,
)

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="potsnitch")
def main():
    """PotSnitch - Low-interaction honeypot detection tool.

    Detect honeypots for defensive validation of your deployments.
    """
    pass


@main.command()
@click.argument("target")
@click.option(
    "--ports", "-p",
    help="Comma-separated ports to scan (default: auto-detect from modules)",
)
@click.option(
    "--modules", "-m",
    help="Comma-separated detector modules to use (default: all)",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json", "csv"]),
    default="table",
    help="Output format",
)
@click.option(
    "--timeout", "-t",
    type=float,
    default=5.0,
    help="Connection timeout in seconds",
)
@click.option(
    "--workers", "-w",
    type=int,
    default=10,
    help="Maximum concurrent workers",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
def scan(target, ports, modules, output, timeout, workers, verbose):
    """Scan target for honeypots.

    TARGET can be an IP address, hostname, or CIDR range.

    Examples:

        potsnitch scan 192.168.1.100

        potsnitch scan 192.168.1.0/24 --modules ssh,dionaea

        potsnitch scan target.com --ports 22,445,3389 --output json
    """
    scanner = HoneypotScanner(timeout=timeout, max_workers=workers, verbose=verbose)

    # Parse ports
    port_list = None
    if ports:
        try:
            port_list = [int(p.strip()) for p in ports.split(",")]
        except ValueError:
            console.print("[red]Error: Invalid port format[/red]")
            sys.exit(1)

    # Parse modules
    module_list = None
    if modules:
        module_list = [m.strip() for m in modules.split(",")]

    # Check if target is a range
    if "/" in target:
        with console.status(f"Scanning network {target}..."):
            reports = scanner.scan_range(target, ports=port_list, modules=module_list)

        if not reports:
            console.print("[green]No honeypots detected in range[/green]")
            return

        for report in reports:
            _output_report(report, output)
    else:
        with console.status(f"Scanning {target}..."):
            report = scanner.scan(target, ports=port_list, modules=module_list)

        _output_report(report, output)


@main.command()
@click.argument("honeypot_type")
@click.argument("target")
@click.option(
    "--port", "-p",
    type=int,
    help="Port to validate (default: auto-detect)",
)
@click.option(
    "--timeout", "-t",
    type=float,
    default=5.0,
    help="Connection timeout in seconds",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Enable verbose output",
)
def validate(honeypot_type, target, port, timeout, verbose):
    """Validate your honeypot deployment for fingerprinting weaknesses.

    HONEYPOT_TYPE is the type of honeypot (e.g., cowrie, dionaea, conpot).
    TARGET is the IP address or hostname of your honeypot.

    Examples:

        potsnitch validate cowrie 192.168.1.100

        potsnitch validate dionaea 192.168.1.100 --port 445

        potsnitch validate conpot 10.0.0.50
    """
    scanner = HoneypotScanner(timeout=timeout, verbose=verbose)

    try:
        with console.status(f"Validating {honeypot_type} honeypot at {target}..."):
            result, recommendations = scanner.validate(target, honeypot_type, port)
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print("\nAvailable honeypot types:")
        for module in scanner.list_modules():
            for hp_type in module["honeypot_types"]:
                console.print(f"  - {hp_type}")
        sys.exit(1)

    print_validation_report(target, honeypot_type, result, recommendations)


@main.command("list-modules")
def list_modules():
    """List all available detector modules."""
    modules = HoneypotScanner.list_modules()

    console.print("\n[bold]Available Detector Modules[/bold]\n")

    for module in modules:
        console.print(f"[cyan]{module['name']}[/cyan]")
        console.print(f"  {module['description']}")
        console.print(f"  [dim]Honeypot types:[/dim] {', '.join(module['honeypot_types'])}")
        console.print(f"  [dim]Default ports:[/dim] {', '.join(map(str, module['default_ports']))}")
        console.print()


def _output_report(report, output_format):
    """Output report in specified format."""
    if output_format == "json":
        print(format_json(report))
    elif output_format == "csv":
        print(format_csv(report))
    else:
        format_table(report)


if __name__ == "__main__":
    main()
