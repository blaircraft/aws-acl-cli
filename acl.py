#!/usr/bin/env python3

import boto3
import click
import random
import string
import re
import sys
from enum import Enum
from botocore.exceptions import ClientError

# Protocol mapping
PROTOCOL_MAP = {
    "tcp": "6",
    "udp": "17",
    "icmp": "1",
    "all": "-1",
}

class ErrorCategory(Enum):
    CONFIG = "Configuration Error"
    PERMISSION = "Permission Error"
    INPUT = "Input Error"
    AWS = "AWS API Error"
    UNKNOWN = "Unknown Error"

def handle_error(error, category, context=None, suggestions=None):
    """Centralized error handler with actionable suggestions"""
    error_msg = f"\n[{category.value}] "
    if context:
        error_msg += f"{context}: "

    error_msg += f"{str(error)}"
    print(error_msg, file=sys.stderr)

    if suggestions:
        print("\nSuggested actions:", file=sys.stderr)
        for suggestion in suggestions:
            print(f"  - {suggestion}", file=sys.stderr)

    if category == ErrorCategory.CONFIG:
        print("\nRun 'aws configure --profile <profile-name>' to set up your AWS credentials.", file=sys.stderr)
    elif category == ErrorCategory.PERMISSION:
        print("\nEnsure your AWS profile has the following permissions:", file=sys.stderr)
        print("  - ec2:CreateNetworkAcl", file=sys.stderr)
        print("  - ec2:CreateNetworkAclEntry", file=sys.stderr)
        print("  - ec2:DeleteNetworkAcl", file=sys.stderr)
        print("  - ec2:DeleteNetworkAclEntry", file=sys.stderr)
        print("  - ec2:DescribeNetworkAcls", file=sys.stderr)

# Function to generate a random name for the network ACL
def generate_random_name(length=8):
    return "nacl-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))

def validate_cidr(cidr):
    """Validate CIDR block format."""
    pattern = r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$'
    if not re.match(pattern, cidr):
        return False

    # Validate IP address portion
    try:
        ip_part = cidr.split('/')[0]
        octets = ip_part.split('.')
        for octet in octets:
            if not 0 <= int(octet) <= 255:
                return False

        # Validate prefix length
        prefix = int(cidr.split('/')[1])
        if not 0 <= prefix <= 32:
            return False

        return True
    except (ValueError, IndexError):
        return False

# Function to parse the network ACL file
def parse_acl_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    acl_rules = {"inbound": [], "outbound": []}
    current_section = None
    line_number = 0

    for line in lines:
        line_number += 1
        line = line.strip()

        # Skip empty lines or comments
        if not line or line.startswith('#'):
            continue

        if line.startswith("[inbound]"):
            current_section = "inbound"
        elif line.startswith("[outbound]"):
            current_section = "outbound"
        elif current_section and line:
            parts = line.split()
            if len(parts) == 5:
                # Validate rule number
                try:
                    rule_number = int(parts[0])
                    if not 1 <= rule_number <= 32766:
                        raise ValueError(f"Rule number must be between 1 and 32766 (line {line_number}): {line}")
                except ValueError:
                    raise ValueError(f"Invalid rule number format (line {line_number}): {line}")

                # Map protocol to numeric value
                protocol = PROTOCOL_MAP.get(parts[1].lower())
                if protocol is None:
                    raise ValueError(f"Invalid protocol '{parts[1]}' (line {line_number}): {line}")

                # Validate port range
                port_range = parts[2]
                if port_range != "-" and protocol != "-1":
                    if "-" in port_range:
                        try:
                            from_port, to_port = map(int, port_range.split("-"))
                            if not 0 <= from_port <= 65535 or not 0 <= to_port <= 65535:
                                raise ValueError(f"Port must be between 0 and 65535 (line {line_number}): {line}")
                            if from_port > to_port:
                                raise ValueError(f"Invalid port range: from_port > to_port (line {line_number}): {line}")
                        except ValueError as e:
                            if "Port must be" in str(e) or "Invalid port range" in str(e):
                                raise e
                            raise ValueError(f"Invalid port range format (line {line_number}): {line}")
                    else:
                        try:
                            port = int(port_range)
                            if not 0 <= port <= 65535:
                                raise ValueError(f"Port must be between 0 and 65535 (line {line_number}): {line}")
                        except ValueError:
                            raise ValueError(f"Invalid port format (line {line_number}): {line}")

                # Validate CIDR block
                cidr_block = "0.0.0.0/0" if parts[3] == "0/0" else parts[3]
                if not validate_cidr(cidr_block):
                    raise ValueError(f"Invalid CIDR block format (line {line_number}): {line}")

                # Validate action
                action = parts[4].lower()
                if action not in ["allow", "deny"]:
                    raise ValueError(f"Action must be 'allow' or 'deny' (line {line_number}): {line}")

                rule = {
                    "rule_number": rule_number,
                    "protocol": protocol,
                    "port_range": port_range,
                    "cidr_block": cidr_block,
                    "action": action
                }
                acl_rules[current_section].append(rule)
            else:
                raise ValueError(f"Invalid rule format (line {line_number}): {line}")

    # Validate that at least one section has rules
    if not acl_rules["inbound"] and not acl_rules["outbound"]:
        raise ValueError("ACL file must contain at least one inbound or outbound rule")

    return acl_rules

# Function to add rules to a Network ACL
def add_acl_rules(client, acl_id, acl_rules):
    success_count = 0
    total_rules = sum(len(rules) for rules in acl_rules.values())

    for direction, rules in acl_rules.items():
        for rule in rules:
            params = {
                "NetworkAclId": acl_id,
                "RuleNumber": rule["rule_number"],
                "Protocol": rule["protocol"],
                "RuleAction": rule["action"],
                "Egress": (direction == "outbound"),
                "CidrBlock": rule["cidr_block"]
            }

            # Only include PortRange for applicable protocols
            if rule["protocol"] != "-1":
                try:
                    if "-" in rule["port_range"]:
                        from_port, to_port = map(int, rule["port_range"].split("-"))
                    else:
                        from_port = to_port = int(rule["port_range"])

                    params["PortRange"] = {
                        "From": from_port,
                        "To": to_port
                    }
                except ValueError:
                    print(f"ERROR: Invalid port range '{rule['port_range']}' in {direction} rule {rule['rule_number']}")
                    continue

            # Add the rule to the ACL
            try:
                client.create_network_acl_entry(**params)
                success_count += 1
                print(f"Added {direction} rule: {rule}")
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'NetworkAclEntryLimitExceeded':
                    print(f"ERROR: Cannot add {direction} rule {rule['rule_number']}: Maximum number of rules exceeded")
                elif error_code == 'NetworkAclEntryAlreadyExists':
                    print(f"ERROR: Cannot add {direction} rule {rule['rule_number']}: Rule number already exists")
                else:
                    print(f"ERROR: Failed to add {direction} rule {rule['rule_number']}: {e.response['Error']['Message']}")

    if success_count < total_rules:
        print(f"WARNING: Only {success_count} of {total_rules} rules were successfully added")
    else:
        print(f"SUCCESS: All {total_rules} rules were successfully added to ACL {acl_id}")


@click.group()
@click.option("--profile", "-p", required=True, help="AWS profile")
@click.option("--region", "-r", default="ca-central-1", help="AWS region (default: ca-central-1)")
@click.pass_context
def acl(ctx, profile, region):
    """Manage AWS Network ACLs and VPCs."""
    ctx.ensure_object(dict)
    ctx.obj["profile"] = profile
    ctx.obj["region"] = region


@acl.command()
@click.option("--vpc-id", "-v", required=True, help="AWS VPC in which to create the network ACL")
@click.option("--network-acl", "-n", type=click.Path(exists=True), help="Path to the text file containing the network ACL")
@click.option("--acl-name", "-a", default=None, help="Name of the network ACL (default: randomly generated)")
@click.option("--rollback-on-failure/--no-rollback-on-failure", default=True, 
              help="Delete the ACL if rule creation fails (default: enabled)")
@click.pass_context
def create(ctx, vpc_id, network_acl, acl_name, rollback_on_failure):
    """Create a new network ACL in the specified VPC."""
    try:
        session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
        client = session.client("ec2")
    except Exception as e:
        handle_error(
            e, 
            ErrorCategory.CONFIG, 
            "Failed to initialize AWS client",
            ["Check if your AWS profile is correctly configured",
             f"Verify AWS region '{ctx.obj['region']}' is valid"]
        )
        return

    acl_name = acl_name or generate_random_name()
    acl_id = None

    if not network_acl:
        handle_error(
            "No ACL file provided", 
            ErrorCategory.INPUT, 
            suggestions=["Specify an ACL file with --network-acl option",
                         f"Example: acl --profile {ctx.obj['profile']} create --vpc-id {vpc_id} --network-acl ./sample.acl"]
        )
        return

    try:
        # Parse ACL file first to validate it before creating any resources
        acl_rules = parse_acl_file(network_acl)

        # Create the Network ACL
        try:
            response = client.create_network_acl(VpcId=vpc_id, TagSpecifications=[
                {
                    "ResourceType": "network-acl",
                    "Tags": [{"Key": "Name", "Value": acl_name}]
                }
            ])
            acl_id = response["NetworkAcl"]["NetworkAclId"]
            print(f"Created Network ACL with ID: {acl_id}")

            # Add ACL rules
            rules_success = True
            try:
                add_acl_rules(client, acl_id, acl_rules)
            except Exception as e:
                rules_success = False
                print(f"Error adding ACL rules: {str(e)}")

                # Rollback if requested
                if rollback_on_failure and acl_id:
                    print(f"Rolling back: Deleting Network ACL {acl_id}")
                    try:
                        client.delete_network_acl(NetworkAclId=acl_id)
                        print(f"Successfully deleted Network ACL {acl_id}")
                        acl_id = None
                    except ClientError as delete_error:
                        print(f"ERROR: Failed to delete ACL during rollback: {delete_error.response['Error']['Message']}")
                        print(f"You may need to manually delete ACL {acl_id}")

            if acl_id and rules_success:
                print(f"Successfully created Network ACL {acl_id} with all rules")

        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == 'InvalidVpcID.NotFound':
                handle_error(
                    f"VPC {vpc_id} not found",
                    ErrorCategory.INPUT,
                    "Failed to create Network ACL",
                    [f"Verify that VPC ID {vpc_id} exists in region {ctx.obj['region']}",
                     "Run 'aws ec2 describe-vpcs' to list available VPCs"]
                )
            else:
                handle_error(
                    e.response['Error']['Message'],
                    ErrorCategory.AWS,
                    "Failed to create Network ACL",
                    ["Check your AWS permissions and VPC configuration"]
                )

    except FileNotFoundError:
        handle_error(
            f"ACL file '{network_acl}' not found",
            ErrorCategory.INPUT,
            suggestions=[f"Check if the file path is correct: {network_acl}",
                        "Use an absolute path to the ACL file"]
        )
    except ValueError as e:
        handle_error(
            str(e),
            ErrorCategory.INPUT,
            "Invalid ACL file format",
            ["Check your ACL file syntax",
             "Refer to the documentation for the correct format"]
        )
    except Exception as e:
        handle_error(
            str(e),
            ErrorCategory.UNKNOWN,
            "Unexpected error occurred",
            ["Check the console output for more details"]
        )

    # Final status report
    if acl_id:
        print(f"Operation completed. Network ACL ID: {acl_id}")
        return acl_id
    else:
        print("Operation failed. No Network ACL was created.")
        return None


@acl.command()
@click.option("--acl-id", "-a", required=True, help="ID of the Network ACL to modify")
@click.option("--network-acl", "-n", type=click.Path(exists=True), help="Path to the text file containing the network ACL")
@click.pass_context
def modify(ctx, acl_id, network_acl):
    """Modify an existing network ACL."""
    try:
        session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
        client = session.client("ec2")
    except Exception as e:
        handle_error(
            e, 
            ErrorCategory.CONFIG, 
            "Failed to initialize AWS client",
            ["Check if your AWS profile is correctly configured",
             f"Verify AWS region '{ctx.obj['region']}' is valid"]
        )
        return

    if not network_acl:
        handle_error(
            "No ACL file provided", 
            ErrorCategory.INPUT, 
            suggestions=["Specify an ACL file with --network-acl option",
                         f"Example: acl --profile {ctx.obj['profile']} modify --acl-id {acl_id} --network-acl ./sample.acl"]
        )
        return

    try:
        # First check if the ACL exists
        try:
            client.describe_network_acls(NetworkAclIds=[acl_id])
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidNetworkAclID.NotFound':
                handle_error(
                    f"Network ACL {acl_id} not found",
                    ErrorCategory.INPUT,
                    "Failed to modify Network ACL",
                    [f"Verify that ACL ID {acl_id} exists in region {ctx.obj['region']}",
                     "Run 'aws ec2 describe-network-acls' to list available ACLs"]
                )
                return
            raise

        # Parse the ACL file
        acl_rules = parse_acl_file(network_acl)
        print(f"Modifying Network ACL with ID: {acl_id}")

        # Clear existing rules
        for direction in ["inbound", "outbound"]:
            try:
                entries = client.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
                for entry in entries:
                    if (
                        entry["Egress"] == (direction == "outbound") and
                        not entry.get("Default", False) and  # Skip default rules
                        1 <= entry["RuleNumber"] <= 32766  # Ensure valid rule numbers
                    ):
                        try:
                            client.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=entry["RuleNumber"], Egress=entry["Egress"])
                            print(f"Deleted {direction} rule with RuleNumber: {entry['RuleNumber']}")
                        except ClientError as e:
                            print(f"WARNING: Could not delete {direction} rule {entry['RuleNumber']}: {e.response['Error']['Message']}")
            except ClientError as e:
                handle_error(
                    e.response['Error']['Message'],
                    ErrorCategory.AWS,
                    f"Failed to clear existing {direction} rules",
                    ["Check your AWS permissions"]
                )
                return

        # Add new rules
        add_acl_rules(client, acl_id, acl_rules)
        print(f"Modified Network ACL {acl_id} successfully.")
    except FileNotFoundError:
        handle_error(
            f"ACL file '{network_acl}' not found",
            ErrorCategory.INPUT,
            suggestions=[f"Check if the file path is correct: {network_acl}",
                        "Use an absolute path to the ACL file"]
        )
    except ValueError as e:
        handle_error(
            str(e),
            ErrorCategory.INPUT,
            "Invalid ACL file format",
            ["Check your ACL file syntax",
             "Refer to the documentation for the correct format"]
        )
    except Exception as e:
        handle_error(
            str(e),
            ErrorCategory.UNKNOWN,
            "Unexpected error occurred",
            ["Check the console output for more details"]
        )


@acl.command()
@click.argument("network-acl-id")
@click.option("--force", "-f", is_flag=True, help="Force deletion without confirmation")
@click.pass_context
def delete(ctx, network_acl_id, force):
    """Delete the specified Network ACL."""
    try:
        session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
        client = session.client("ec2")
    except Exception as e:
        handle_error(
            e, 
            ErrorCategory.CONFIG, 
            "Failed to initialize AWS client",
            ["Check if your AWS profile is correctly configured",
             f"Verify AWS region '{ctx.obj['region']}' is valid"]
        )
        return

    try:
        # Describe the Network ACL to ensure it exists and is not the default
        try:
            acl = client.describe_network_acls(NetworkAclIds=[network_acl_id])["NetworkAcls"][0]
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidNetworkAclID.NotFound':
                handle_error(
                    f"Network ACL {network_acl_id} not found",
                    ErrorCategory.INPUT,
                    "Failed to delete Network ACL",
                    [f"Verify that ACL ID {network_acl_id} exists in region {ctx.obj['region']}",
                     "Run 'aws ec2 describe-network-acls' to list available ACLs"]
                )
                return
            raise

        if acl.get("IsDefault", False):
            handle_error(
                f"Cannot delete Network ACL {network_acl_id}: It is the default ACL.",
                ErrorCategory.INPUT,
                "Failed to delete Network ACL",
                ["Default Network ACLs cannot be deleted",
                 "Create a new ACL to replace the default one"]
            )
            return

        # Confirmation prompt if not using --force
        if not force:
            print(f"Are you sure you want to delete Network ACL {network_acl_id}? This action cannot be undone.")
            print("Type 'yes' to confirm: ", end="")
            confirm = input()
            if confirm.lower() != "yes":
                print("Deletion cancelled.")
                return

        print(f"Deleting Network ACL: {network_acl_id}")

        # Delete all custom rules (entries) in the ACL
        for entry in acl["Entries"]:
            if not entry.get("Default", False):  # Skip default rules
                try:
                    client.delete_network_acl_entry(
                        NetworkAclId=network_acl_id,
                        RuleNumber=entry["RuleNumber"],
                        Egress=entry["Egress"]
                    )
                    print(f"Deleted rule: RuleNumber={entry['RuleNumber']}, Egress={entry['Egress']}")
                except ClientError as e:
                    print(f"WARNING: Failed to delete rule {entry['RuleNumber']}: {e.response['Error']['Message']}")

        # Delete the ACL itself
        try:
            client.delete_network_acl(NetworkAclId=network_acl_id)
            print(f"Deleted Network ACL: {network_acl_id}")
        except ClientError as e:
            if "has dependencies" in e.response['Error']['Message']:
                handle_error(
                    e.response['Error']['Message'],
                    ErrorCategory.AWS,
                    f"Failed to delete Network ACL {network_acl_id}",
                    ["The ACL might be associated with subnets",
                     "Disassociate the ACL from all subnets before deleting"]
                )
            else:
                handle_error(
                    e.response['Error']['Message'],
                    ErrorCategory.AWS,
                    f"Failed to delete Network ACL {network_acl_id}"
                )

    except ClientError as e:
        handle_error(
            e.response['Error']['Message'],
            ErrorCategory.AWS,
            f"Failed to delete Network ACL {network_acl_id}"
        )
    except Exception as e:
        handle_error(
            str(e),
            ErrorCategory.UNKNOWN,
            "Unexpected error occurred",
            ["Check the console output for more details"]
        )


@acl.command()
@click.option("--vpc-id", "-v", required=True, help="AWS VPC ID to query for network ACLs")
@click.option("--subnet", "-s", help="AWS VPC subnet ID to query (optional)")
@click.option("--markdown", "-m", is_flag=True, help="Output in markdown format")
@click.pass_context
def list(ctx, vpc_id, subnet, markdown):
    """List network ACLs attached to subnets in a VPC.
    
    If --subnet is specified, only shows the ACL attached to that subnet.
    Otherwise, shows ACLs for all subnets in the VPC.
    """
    try:
        session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
        client = session.client("ec2")
    except Exception as e:
        handle_error(
            e, 
            ErrorCategory.CONFIG, 
            "Failed to initialize AWS client",
            ["Check if your AWS profile is correctly configured",
             f"Verify AWS region '{ctx.obj['region']}' is valid"]
        )
        return

    try:
        # Validate VPC exists
        try:
            client.describe_vpcs(VpcIds=[vpc_id])
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidVpcID.NotFound':
                handle_error(
                    f"VPC {vpc_id} not found",
                    ErrorCategory.INPUT,
                    "Failed to list Network ACLs",
                    [f"Verify that VPC ID {vpc_id} exists in region {ctx.obj['region']}",
                     "Run 'aws ec2 describe-vpcs' to list available VPCs"]
                )
                return
            raise

        # Get subnet filters based on input
        subnet_filters = [{"Name": "vpc-id", "Values": [vpc_id]}]
        if subnet:
            subnet_filters.append({"Name": "subnet-id", "Values": [subnet]})
            # Validate subnet exists
            try:
                subnet_response = client.describe_subnets(SubnetIds=[subnet])
                if not subnet_response["Subnets"]:
                    handle_error(
                        f"Subnet {subnet} not found",
                        ErrorCategory.INPUT,
                        "Failed to list Network ACL",
                        [f"Verify that subnet ID {subnet} exists in VPC {vpc_id}",
                         "Run 'aws ec2 describe-subnets --filters Name=vpc-id,Values=vpc-id' to list available subnets"]
                    )
                    return
            except ClientError as e:
                if e.response['Error']['Code'] == 'InvalidSubnetID.NotFound':
                    handle_error(
                        f"Subnet {subnet} not found",
                        ErrorCategory.INPUT,
                        "Failed to list Network ACL",
                        [f"Verify that subnet ID {subnet} exists in VPC {vpc_id}"]
                    )
                    return
                raise

        # Get subnets in the VPC
        subnets = client.describe_subnets(Filters=subnet_filters)["Subnets"]
        if not subnets:
            print(f"No subnets found in VPC {vpc_id}")
            return

        # Get all network ACLs in the VPC
        acls = client.describe_network_acls(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["NetworkAcls"]
        acl_map = {acl["NetworkAclId"]: acl for acl in acls}

        # Reverse PROTOCOL_MAP for displaying protocol names
        REVERSE_PROTOCOL_MAP = {v: k for k, v in PROTOCOL_MAP.items()}

        # Prepare the results
        results = []
        for s in subnets:
            subnet_id = s["SubnetId"]
            cidr_block = s["CidrBlock"]
            az = s["AvailabilityZone"]
            tags = {tag["Key"]: tag["Value"] for tag in s.get("Tags", [])}
            subnet_name = tags.get("Name", "")
            
            # Find the associated network ACL
            acl_id = None
            for acl in acls:
                for assoc in acl["Associations"]:
                    if assoc["SubnetId"] == subnet_id:
                        acl_id = acl["NetworkAclId"]
                        break
                if acl_id:
                    break
            
            if not acl_id:
                continue
                
            # Get ACL details
            is_default = acl_map[acl_id]["IsDefault"] if acl_id in acl_map else False
            acl_tags = {tag["Key"]: tag["Value"] for tag in acl_map[acl_id].get("Tags", [])} if acl_id in acl_map else {}
            acl_name = acl_tags.get("Name", "")
            
            # Extract ACL rules
            inbound_rules = []
            outbound_rules = []
            
            if acl_id in acl_map:
                for entry in acl_map[acl_id]["Entries"]:
                    rule = {
                        "rule_number": entry["RuleNumber"],
                        "protocol": REVERSE_PROTOCOL_MAP.get(str(entry["Protocol"]), str(entry["Protocol"])),
                        "cidr_block": entry.get("CidrBlock", ""),
                        "action": entry["RuleAction"],
                        "is_default": entry.get("Default", False)
                    }
                    
                    # Add port range if available
                    if "PortRange" in entry:
                        from_port = entry["PortRange"]["From"]
                        to_port = entry["PortRange"]["To"]
                        if from_port == to_port:
                            rule["port_range"] = str(from_port)
                        else:
                            rule["port_range"] = f"{from_port}-{to_port}"
                    else:
                        rule["port_range"] = "-"
                    
                    if entry["Egress"]:
                        outbound_rules.append(rule)
                    else:
                        inbound_rules.append(rule)
            
            # Sort rules by rule number
            inbound_rules.sort(key=lambda x: x["rule_number"])
            outbound_rules.sort(key=lambda x: x["rule_number"])
            
            results.append({
                "subnet_id": subnet_id,
                "subnet_name": subnet_name,
                "cidr_block": cidr_block,
                "availability_zone": az,
                "acl_id": acl_id,
                "acl_name": acl_name,
                "is_default": is_default,
                "inbound_rules": inbound_rules,
                "outbound_rules": outbound_rules
            })
        
        # Output the results
        if markdown:
            print("# Network ACLs in VPC " + vpc_id)
            print()
            
            for r in results:
                print(f"## Subnet: {r['subnet_id']}")
                print()
                print(f"- **Subnet Name:** {r['subnet_name']}")
                print(f"- **CIDR Block:** {r['cidr_block']}")
                print(f"- **Availability Zone:** {r['availability_zone']}")
                print(f"- **ACL ID:** {r['acl_id']}")
                print(f"- **ACL Name:** {r['acl_name']}")
                print(f"- **Default ACL:** {'Yes' if r['is_default'] else 'No'}")
                print()
                
                print("### Inbound Rules")
                print()
                print("| Rule # | Protocol | Port/Range | CIDR Block | Action | Default |")
                print("|--------|----------|------------|------------|--------|---------|")
                for rule in r['inbound_rules']:
                    print(f"| {rule['rule_number']} | {rule['protocol']} | {rule['port_range']} | {rule['cidr_block']} | {rule['action']} | {'Yes' if rule['is_default'] else 'No'} |")
                print()
                
                print("### Outbound Rules")
                print()
                print("| Rule # | Protocol | Port/Range | CIDR Block | Action | Default |")
                print("|--------|----------|------------|------------|--------|---------|")
                for rule in r['outbound_rules']:
                    print(f"| {rule['rule_number']} | {rule['protocol']} | {rule['port_range']} | {rule['cidr_block']} | {rule['action']} | {'Yes' if rule['is_default'] else 'No'} |")
                print()
        else:
            if subnet:
                print(f"Network ACL for subnet {subnet} in VPC {vpc_id}:")
            else:
                print(f"Network ACLs for all subnets in VPC {vpc_id}:")
            print()
            
            for r in results:
                print(f"Subnet ID:         {r['subnet_id']}")
                if r['subnet_name']:
                    print(f"Subnet Name:       {r['subnet_name']}")
                print(f"CIDR Block:        {r['cidr_block']}")
                print(f"Availability Zone: {r['availability_zone']}")
                print(f"ACL ID:            {r['acl_id']}")
                if r['acl_name']:
                    print(f"ACL Name:          {r['acl_name']}")
                print(f"Default ACL:       {'Yes' if r['is_default'] else 'No'}")
                print()
                
                print("Inbound Rules:")
                print("-------------")
                print(f"{'Rule #':<8} {'Protocol':<10} {'Port/Range':<12} {'CIDR Block':<18} {'Action':<8} {'Default':<8}")
                print("-" * 70)
                for rule in r['inbound_rules']:
                    print(f"{rule['rule_number']:<8} {rule['protocol']:<10} {rule['port_range']:<12} {rule['cidr_block']:<18} {rule['action']:<8} {'Yes' if rule['is_default'] else 'No':<8}")
                print()
                
                print("Outbound Rules:")
                print("--------------")
                print(f"{'Rule #':<8} {'Protocol':<10} {'Port/Range':<12} {'CIDR Block':<18} {'Action':<8} {'Default':<8}")
                print("-" * 70)
                for rule in r['outbound_rules']:
                    print(f"{rule['rule_number']:<8} {rule['protocol']:<10} {rule['port_range']:<12} {rule['cidr_block']:<18} {rule['action']:<8} {'Yes' if rule['is_default'] else 'No':<8}")
                print()

    except ClientError as e:
        handle_error(
            e.response['Error']['Message'],
            ErrorCategory.AWS,
            f"Failed to list Network ACLs for VPC {vpc_id}"
        )
    except Exception as e:
        handle_error(
            str(e),
            ErrorCategory.UNKNOWN,
            "Failed to list Network ACLs",
            ["Check the AWS permissions for your profile"]
        )


if __name__ == "__main__":
    acl(obj={})
