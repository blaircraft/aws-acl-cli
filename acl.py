#!/usr/bin/env python3

import boto3
import click
import random
import string
from botocore.exceptions import ClientError

# Protocol mapping
PROTOCOL_MAP = {
    "tcp": "6",
    "udp": "17",
    "icmp": "1",
    "all": "-1",
}


# Function to generate a random name for the network ACL
def generate_random_name(length=8):
    return "nacl-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


# Function to parse the network ACL file
def parse_acl_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    acl_rules = {"inbound": [], "outbound": []}
    current_section = None

    for line in lines:
        line = line.strip()
        if line.startswith("[inbound]"):
            current_section = "inbound"
        elif line.startswith("[outbound]"):
            current_section = "outbound"
        elif current_section and line:
            parts = line.split()
            if len(parts) == 5:
                # Map protocol to numeric value and expand 0/0 to 0.0.0.0/0
                protocol = PROTOCOL_MAP.get(parts[1].lower())
                if protocol is None:
                    raise ValueError(f"Invalid protocol '{parts[1]}' in rule: {line}")
                cidr_block = "0.0.0.0/0" if parts[3] == "0/0" else parts[3]
                rule = {
                    "rule_number": int(parts[0]),
                    "protocol": protocol,
                    "port_range": parts[2],
                    "cidr_block": cidr_block,
                    "action": parts[4]
                }
                acl_rules[current_section].append(rule)
            else:
                raise ValueError(f"Invalid rule format: {line}")

    return acl_rules

# Function to add rules to a Network ACL
def add_acl_rules(client, acl_id, acl_rules):
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
                params["PortRange"] = {
                    "From": int(rule["port_range"].split("-")[0]),
                    "To": int(rule["port_range"].split("-")[-1])
                }

            # Add the rule to the ACL
            client.create_network_acl_entry(**params)
            print(f"Added {direction} rule: {rule}")


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
@click.pass_context
def create(ctx, vpc_id, network_acl, acl_name):
    """Create a new network ACL in the specified VPC."""
    session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
    client = session.client("ec2")

    acl_name = acl_name or generate_random_name()

    if network_acl:
        try:
            acl_rules = parse_acl_file(network_acl)
            response = client.create_network_acl(VpcId=vpc_id, TagSpecifications=[
                {
                    "ResourceType": "network-acl",
                    "Tags": [{"Key": "Name", "Value": acl_name}]
                }
            ])
            acl_id = response["NetworkAcl"]["NetworkAclId"]
            print(f"Created Network ACL with ID: {acl_id}")
            add_acl_rules(client, acl_id, acl_rules)
        except Exception as e:
            print(f"Error: {e}")
    else:
        print("No ACL file provided. Exiting.")


@acl.command()
@click.option("--acl-id", "-a", required=True, help="ID of the Network ACL to modify")
@click.option("--network-acl", "-n", type=click.Path(exists=True), help="Path to the text file containing the network ACL")
@click.pass_context
def modify(ctx, acl_id, network_acl):
    """Modify an existing network ACL."""
    session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
    client = session.client("ec2")

    if not network_acl:
        print("No ACL file provided. Exiting.")
        return

    try:
        acl_rules = parse_acl_file(network_acl)
        print(f"Modifying Network ACL with ID: {acl_id}")
        # Clear existing rules
        for direction in ["inbound", "outbound"]:
            entries = client.describe_network_acls(NetworkAclIds=[acl_id])["NetworkAcls"][0]["Entries"]
            for entry in entries:
                if (
                    entry["Egress"] == (direction == "outbound") and
                    not entry.get("Default", False) and  # Skip default rules
                    1 <= entry["RuleNumber"] <= 32766  # Ensure valid rule numbers
                ):
                    client.delete_network_acl_entry(NetworkAclId=acl_id, RuleNumber=entry["RuleNumber"], Egress=entry["Egress"])
                    print(f"Deleted {direction} rule with RuleNumber: {entry['RuleNumber']}")

        # Add new rules
        add_acl_rules(client, acl_id, acl_rules)
        print(f"Modified Network ACL {acl_id} successfully.")
    except Exception as e:
        print(f"Error: {e}")


@acl.command()
@click.argument("network-acl-id")
@click.pass_context
def delete(ctx, network_acl_id):
    """Delete the specified Network ACL."""
    session = boto3.Session(profile_name=ctx.obj["profile"], region_name=ctx.obj["region"])
    ec2 = session.client("ec2")

    try:
        # Describe the Network ACL to ensure it exists and is not the default
        acl = ec2.describe_network_acls(NetworkAclIds=[network_acl_id])["NetworkAcls"][0]
        if acl.get("IsDefault", False):
            print(f"Cannot delete Network ACL {network_acl_id}: It is the default ACL.")
            return

        print(f"Deleting Network ACL: {network_acl_id}")

        # Delete all rules (entries) in the ACL
        for entry in acl["Entries"]:
            ec2.delete_network_acl_entry(
                NetworkAclId=network_acl_id,
                RuleNumber=entry["RuleNumber"],
                Egress=entry["Egress"]
            )
            print(f"Deleted rule: RuleNumber={entry['RuleNumber']}, Egress={entry['Egress']}")

        # Delete the ACL itself
        ec2.delete_network_acl(NetworkAclId=network_acl_id)
        print(f"Deleted Network ACL: {network_acl_id}")

    except ClientError as e:
        print(f"Error: {e.response['Error']['Message']}")


if __name__ == "__main__":
    acl(obj={})
