#!/usr/bin/env python3
"""
Network Analyzer CLI Client
Command line interface untuk berinteraksi dengan server
"""

import argparse
import sys
import os
from client import NetworkAnalyzerClient
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import json

console = Console()


def print_banner():
    """Print CLI banner"""
    banner = """
    ╔═══════════════════════════════════════════╗
    ║   Network Analyzer Client v1.0           ║
    ║   REST API Client                        ║
    ╚═══════════════════════════════════════════╝
    """
    console.print(Panel(banner, style="bold cyan"))


def cmd_health(args):
    """Check server health"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        health = client.health_check()
        console.print("[green]✓ Server is healthy[/green]")
        console.print(f"Service: {health['service']}")
        console.print(f"Version: {health['version']}")
        console.print(f"Status: {health['status']}")
    except Exception as e:
        console.print(f"[red]✗ Server unreachable: {e}[/red]")
        sys.exit(1)


def cmd_upload(args):
    """Upload PCAP file"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        console.print(f"Uploading {args.file}...")
        result = client.upload_pcap(args.file, args.abuseipdb_key)
        
        console.print("[green]✓ Upload successful[/green]")
        console.print(f"Job ID: {result['job_id']}")
        console.print(f"Filename: {result['filename']}")
        console.print(f"Size: {result['size']} bytes")
        console.print(f"\nNext: Run 'netcap-client analyze {result['job_id']}' to start analysis")
    except Exception as e:
        console.print(f"[red]✗ Upload failed: {e}[/red]")
        sys.exit(1)


def cmd_analyze(args):
    """Start analysis"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        console.print(f"Starting analysis for job {args.job_id}...")
        result = client.start_analysis(
            args.job_id,
            rules_dir=args.rules,
            enable_reputation=not args.no_reputation,
            verbose=args.verbose
        )
        
        console.print("[green]✓ Analysis started[/green]")
        console.print(result['message'])
        console.print(f"\nCheck status: netcap-client status {args.job_id}")
    except Exception as e:
        console.print(f"[red]✗ Failed to start analysis: {e}[/red]")
        sys.exit(1)


def cmd_status(args):
    """Check job status"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        status = client.get_status(args.job_id)
        
        # Create status table
        table = Table(title=f"Job Status: {args.job_id}")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Status", status['status'])
        table.add_row("Filename", status.get('filename', '-'))
        table.add_row("Size", f"{status.get('size', 0)} bytes")
        table.add_row("Created", status.get('created_at', '-'))
        
        if 'progress' in status:
            table.add_row("Progress", f"{status['progress']}%")
        
        if status['status'] == 'completed':
            table.add_row("Completed", status.get('completed_at', '-'))
        elif status['status'] == 'failed':
            table.add_row("Error", status.get('error', '-'))
        
        console.print(table)
        
        # Show results summary if completed
        if status['status'] == 'completed' and status.get('results'):
            results = status['results']
            console.print("\n[bold]Analysis Results:[/bold]")
            console.print(f"  Total Packets: {results.get('total_packets', 0)}")
            console.print(f"  Alerts: {results.get('alerts_generated', 0)}")
            console.print(f"  Malicious IPs: {results.get('malicious_ips_found', 0)}")
            console.print(f"\nDownload results: netcap-client download {args.job_id} output/")
        
    except Exception as e:
        console.print(f"[red]✗ Failed to get status: {e}[/red]")
        sys.exit(1)


def cmd_results(args):
    """Get analysis results"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        results = client.get_results(args.job_id)
        
        console.print("[bold]Analysis Results:[/bold]")
        console.print(json.dumps(results['results'], indent=2))
        
        console.print(f"\n[bold]Available Files:[/bold]")
        for file in results['files']:
            console.print(f"  • {file}")
        
    except Exception as e:
        console.print(f"[red]✗ Failed to get results: {e}[/red]")
        sys.exit(1)


def cmd_download(args):
    """Download results"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        console.print(f"Downloading results to {args.output}...")
        client.download_all_results(args.job_id, args.output)
        console.print(f"[green]✓ Results downloaded to {args.output}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Download failed: {e}[/red]")
        sys.exit(1)


def cmd_list(args):
    """List jobs"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        result = client.list_jobs(status=args.status, limit=args.limit)
        jobs = result['jobs']
        
        if not jobs:
            console.print("[yellow]No jobs found[/yellow]")
            return
        
        # Create jobs table
        table = Table(title="Jobs")
        table.add_column("Job ID", style="cyan")
        table.add_column("Filename", style="white")
        table.add_column("Status", style="green")
        table.add_column("Created", style="blue")
        
        for job in jobs:
            status_style = "green" if job['status'] == 'completed' else "yellow"
            table.add_row(
                job['job_id'][:8] + "...",
                job.get('filename', '-'),
                f"[{status_style}]{job['status']}[/{status_style}]",
                job.get('created_at', '-')[:19]
            )
        
        console.print(table)
        console.print(f"\nTotal: {result['total']} jobs")
        
    except Exception as e:
        console.print(f"[red]✗ Failed to list jobs: {e}[/red]")
        sys.exit(1)


def cmd_delete(args):
    """Delete job"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        if not args.force:
            confirm = input(f"Delete job {args.job_id}? (y/N): ")
            if confirm.lower() != 'y':
                console.print("Cancelled")
                return
        
        result = client.delete_job(args.job_id)
        console.print(f"[green]✓ {result['message']}[/green]")
    except Exception as e:
        console.print(f"[red]✗ Failed to delete job: {e}[/red]")
        sys.exit(1)


def cmd_run(args):
    """Complete workflow: upload + analyze + download"""
    client = NetworkAnalyzerClient(args.server)
    
    try:
        results = client.analyze_pcap(
            filepath=args.file,
            output_dir=args.output,
            abuseipdb_key=args.abuseipdb_key,
            rules_dir=args.rules,
            enable_reputation=not args.no_reputation,
            verbose=args.verbose
        )
        
        console.print("\n[bold green]✓ Analysis Complete![/bold green]")
        console.print(f"Total Packets: {results['results']['total_packets']}")
        console.print(f"Alerts: {results['results']['alerts_generated']}")
        console.print(f"Malicious IPs: {results['results']['malicious_ips_found']}")
        console.print(f"Results saved to: {args.output}")
        
    except Exception as e:
        console.print(f"[red]✗ Analysis failed: {e}[/red]")
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Network Analyzer Client - REST API Client for PCAP analysis",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    parser.add_argument(
        '--server',
        default='http://localhost:5000',
        help='Server URL (default: http://localhost:5000)'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Commands')
    
    # Health check
    subparsers.add_parser('health', help='Check server health')
    
    # Upload
    upload_parser = subparsers.add_parser('upload', help='Upload PCAP file')
    upload_parser.add_argument('file', help='PCAP file to upload')
    upload_parser.add_argument('--abuseipdb-key', help='AbuseIPDB API key')
    
    # Analyze
    analyze_parser = subparsers.add_parser('analyze', help='Start analysis')
    analyze_parser.add_argument('job_id', help='Job ID')
    analyze_parser.add_argument('--rules', default='rules', help='Rules directory')
    analyze_parser.add_argument('--no-reputation', action='store_true', help='Disable reputation')
    analyze_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    
    # Status
    status_parser = subparsers.add_parser('status', help='Check job status')
    status_parser.add_argument('job_id', help='Job ID')
    
    # Results
    results_parser = subparsers.add_parser('results', help='Get analysis results')
    results_parser.add_argument('job_id', help='Job ID')
    
    # Download
    download_parser = subparsers.add_parser('download', help='Download results')
    download_parser.add_argument('job_id', help='Job ID')
    download_parser.add_argument('output', help='Output directory')
    
    # List
    list_parser = subparsers.add_parser('list', help='List jobs')
    list_parser.add_argument('--status', help='Filter by status')
    list_parser.add_argument('--limit', type=int, default=50, help='Max results')
    
    # Delete
    delete_parser = subparsers.add_parser('delete', help='Delete job')
    delete_parser.add_argument('job_id', help='Job ID')
    delete_parser.add_argument('-f', '--force', action='store_true', help='No confirmation')
    
    # Run (complete workflow)
    run_parser = subparsers.add_parser('run', help='Complete workflow (upload+analyze+download)')
    run_parser.add_argument('file', help='PCAP file')
    run_parser.add_argument('-o', '--output', default='output', help='Output directory')
    run_parser.add_argument('--abuseipdb-key', help='AbuseIPDB API key')
    run_parser.add_argument('--rules', default='rules', help='Rules directory')
    run_parser.add_argument('--no-reputation', action='store_true', help='Disable reputation')
    run_parser.add_argument('-v', '--verbose', action='store_true', help='Verbose')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    print_banner()
    
    # Route to appropriate command
    commands = {
        'health': cmd_health,
        'upload': cmd_upload,
        'analyze': cmd_analyze,
        'status': cmd_status,
        'results': cmd_results,
        'download': cmd_download,
        'list': cmd_list,
        'delete': cmd_delete,
        'run': cmd_run
    }
    
    commands[args.command](args)


if __name__ == '__main__':
    main()