# discover_aws_resources.py
import boto3
import typer
import json
import re
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.table import Table
from botocore.exceptions import BotoCoreError, ClientError
from typing_extensions import Annotated

# --- CLI App and Console Setup ---
app = typer.Typer(
    help="🚀 A tool to discover AWS resources and generate a Pulumi import file.",
    add_completion=False
)
console = Console()

# --- Utility Functions ---
def sanitize_name(name: str) -> str:
    """Sanitizes a string to be a valid Pulumi resource name."""
    if not name:
        return "unnamed-resource"
    name = re.sub(r'[^a-zA-Z0-9-]', '-', name)
    name = re.sub(r'-+', '-', name)
    name = name.strip('-')
    return name if name else "unnamed-resource"

def get_name_from_tags(tags: list, default_name: str) -> str:
    """Tries to find a 'Name' tag, otherwise returns a sanitized default name."""
    for tag in tags or []:
        if tag.get('Key') == 'Name':
            return sanitize_name(tag.get('Value', ''))
    return sanitize_name(default_name)

# --- Discovery Functions ---
# Each function now simply returns a list of resource dicts.
# The progress bar and logging are handled by the main command.

def discover_ec2(client):
    resources = []
    for page in client.get_paginator('describe_vpcs').paginate():
        for vpc in page['Vpcs']:
            resources.append({"type": "aws:ec2/vpc:Vpc", "name": get_name_from_tags(vpc.get('Tags'), f"vpc-{vpc['VpcId']}"), "id": vpc['VpcId']})
    for page in client.get_paginator('describe_subnets').paginate():
        for subnet in page['Subnets']:
            resources.append({"type": "aws:ec2/subnet:Subnet", "name": get_name_from_tags(subnet.get('Tags'), f"subnet-{subnet['SubnetId']}"), "id": subnet['SubnetId']})
    for page in client.get_paginator('describe_security_groups').paginate():
        for sg in page['SecurityGroups']:
            resources.append({"type": "aws:ec2/securityGroup:SecurityGroup", "name": sanitize_name(sg.get('GroupName', f"sg-{sg['GroupId']}")), "id": sg['GroupId']})
    for page in client.get_paginator('describe_route_tables').paginate():
        for rt in page['RouteTables']:
            resources.append({"type": "aws:ec2/routeTable:RouteTable", "name": get_name_from_tags(rt.get('Tags'), f"rt-{rt['RouteTableId']}"), "id": rt['RouteTableId']})
    for page in client.get_paginator('describe_internet_gateways').paginate():
        for igw in page['InternetGateways']:
            resources.append({"type": "aws:ec2/internetGateway:InternetGateway", "name": get_name_from_tags(igw.get('Tags'), f"igw-{igw['InternetGatewayId']}"), "id": igw['InternetGatewayId']})
    for page in client.get_paginator('describe_instances').paginate(Filters=[{'Name': 'instance-state-name', 'Values': ['pending', 'running', 'stopping', 'stopped']}]):
        for r in page['Reservations']:
            for i in r['Instances']:
                resources.append({"type": "aws:ec2/instance:Instance", "name": get_name_from_tags(i.get('Tags'), f"instance-{i['InstanceId']}"), "id": i['InstanceId']})
    return resources

def discover_rds(client):
    resources = []
    for page in client.get_paginator('describe_db_instances').paginate():
        for db in page['DBInstances']:
            resources.append({"type": "aws:rds/instance:Instance", "name": sanitize_name(db['DBInstanceIdentifier']), "id": db['DBInstanceIdentifier']})
    return resources

def discover_glue(client):
    resources = []
    for page in client.get_paginator('get_crawlers').paginate():
        for crawler in page['Crawlers']:
            resources.append({"type": "aws:glue/crawler:Crawler", "name": sanitize_name(crawler['Name']), "id": crawler['Name']})
    for page in client.get_paginator('get_jobs').paginate():
        for job in page['Jobs']:
            resources.append({"type": "aws:glue/job:Job", "name": sanitize_name(job['Name']), "id": job['Name']})
    return resources

def discover_s3(client):
    resources = []
    for bucket in client.list_buckets()['Buckets']:
        resources.append({"type": "aws:s3/bucket:Bucket", "name": sanitize_name(bucket['Name']), "id": bucket['Name']})
    return resources

def discover_iam(client):
    resources = []
    for page in client.get_paginator('list_roles').paginate():
        for role in page['Roles']:
            if "aws-service-role" not in role['Path']:
                resources.append({"type": "aws:iam/role:Role", "name": sanitize_name(role['RoleName']), "id": role['RoleName']})
    return resources

def discover_elbv2(client):
    resources = []
    for page in client.get_paginator('describe_load_balancers').paginate():
        for lb in page['LoadBalancers']:
            resources.append({"type": "aws:lb/loadBalancer:LoadBalancer", "name": sanitize_name(lb['LoadBalancerName']), "id": lb['LoadBalancerArn']})
    for page in client.get_paginator('describe_target_groups').paginate():
        for tg in page['TargetGroups']:
            resources.append({"type": "aws:lb/targetGroup:TargetGroup", "name": sanitize_name(tg['TargetGroupName']), "id": tg['TargetGroupArn']})
    return resources

# --- Typer Main Command ---
@app.command()
def main(
    region: Annotated[str, typer.Option(help="The AWS region to scan.", envvar="AWS_REGION")] = None,
    profile: Annotated[str, typer.Option(help="The AWS profile to use.", envvar="AWS_PROFILE")] = None,
    output_file: Annotated[str, typer.Option("--out", "-o", help="The path for the output JSON file.")] = "pulumi_import.json"
):
    """
    Scans an AWS account and generates a Pulumi import file.
    """
    console.print(f"[bold cyan]🚀 Starting AWS Resource Discovery[/bold cyan]")
    
    try:
        session = boto3.Session(profile_name=profile, region_name=region)
        # If region is still None, try to get it from the session
        if not region:
            region = session.region_name
        if not region:
            console.print("[bold red]Error:[/bold red] AWS region not found. Please configure it via AWS_REGION env var, profile, or the --region option.")
            raise typer.Exit(1)
        
        console.print(f"✅ [bold]Profile:[/] [green]{session.profile_name or 'default'}[/green]")
        console.print(f"🌍 [bold]Region:[/] [green]{region}[/green]\n")
    except (BotoCoreError, ClientError) as e:
        console.print(f"[bold red]Error setting up AWS session:[/] {e}")
        raise typer.Exit(1)
    
    discovery_map = {
        "EC2 & VPC": (discover_ec2, "ec2"),
        "RDS": (discover_rds, "rds"),
        "Glue": (discover_glue, "glue"),
        "ELBv2": (discover_elbv2, "elbv2"),
        "IAM": (discover_iam, "iam"),
        "S3": (discover_s3, "s3"),
    }
    
    all_results = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[yellow]Scanning AWS services...", total=len(discovery_map))
        for service_name, (discover_func, client_name) in discovery_map.items():
            progress.update(task, description=f"[yellow]Scanning {service_name}...")
            try:
                client_region = region if client_name not in ["iam", "s3"] else None
                client = session.client(client_name, region_name=client_region)
                all_results[service_name] = discover_func(client)
            except ClientError as e:
                if "AccessDenied" in str(e):
                    console.print(f"\n[bold yellow]⚠️ Access Denied:[/] Skipping {service_name}. Check IAM permissions.")
                else:
                    console.print(f"\n[bold red]ERROR:[/] An error occurred with {service_name}: {e}")
                all_results[service_name] = [] # Ensure key exists
            progress.advance(task)
        progress.update(task, description="[bold green]Scan Complete!")

    # --- Summary Table ---
    table = Table(title="✨ Discovery Summary ✨", title_style="bold magenta", show_header=True, header_style="bold blue")
    table.add_column("Service", style="cyan")
    table.add_column("Resources Found", style="green", justify="right")

    total_resources = 0
    flat_resource_list = []
    for service_name, resources in all_results.items():
        count = len(resources)
        if count > 0:
            table.add_row(service_name, str(count))
            total_resources += count
            flat_resource_list.extend(resources)
    
    console.print(table)
    
    if total_resources == 0:
        console.print("\n[bold yellow]No resources were found. Check your region and permissions.[/bold yellow]")
        raise typer.Exit()
    
    # --- Write Output File ---
    output_data = {"resources": flat_resource_list}
    try:
        with open(output_file, 'w') as f:
            json.dump(output_data, f, indent=4)
        console.print(f"\n[bold green]Success![/bold green] ✅")
        console.print(f"Wrote [bold]{total_resources}[/bold] resources to [cyan]'{output_file}'[/cyan].")
    except IOError as e:
        console.print(f"\n[bold red]Error writing to file:[/] {e}")
        raise typer.Exit(1)
        
    # --- Final Instructions ---
    console.print("\n[bold]Next Steps:[/bold]")
    console.print(f"1. Move [cyan]'{output_file}'[/cyan] to your Pulumi project directory.")
    console.print("2. Run [bold]`pulumi import --file {output_file}`[/bold].")
    console.print("3. [bold yellow]CRITICAL:[/bold yellow] Refactor the generated code to use resource references (e.g., `vpc_id=my_vpc.id`) instead of hardcoded IDs.")

if __name__ == "__main__":
    app()
