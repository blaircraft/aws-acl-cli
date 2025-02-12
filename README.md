# ACL - AWS Network ACL Management

## Overview

The `acl` tool is a command-line utility for managing AWS Network ACLs (NACLs) within a specified VPC. It allows users to create, modify, and delete network ACLs using a structured text format or command-line options. This tool is useful for automating the management of network security rules in AWS environments.

## Features

- Create new AWS Network ACLs within a specified VPC.
- Modify existing ACL rules.
- Delete ACLs when no longer needed.
- Uses an easily readable file format (`acl-file`) for defining ACL rules.

## Installation

Ensure you have Python 3 installed, then install the required dependencies:

```sh
pip install -r requirements.txt
```

Clone the repository and navigate to the directory:

```sh
git clone https://github.com/blaircraft/aws-acl-cli
cd aws-acl-cli
```

## Usage

The `acl` command supports the following options and subcommands:

### Global Options

| Option           | Description                                      |
|-----------------|--------------------------------------------------|
| `--profile, -p` | Specify the AWS profile to use for authentication. (Required) |
| `--region, -r`  | Specify the AWS region to use (default: `ca-central-1`). |

### Subcommands

#### Create a new Network ACL

```sh
acl create --vpc-id vpc-12345678
```

#### Modify an existing Network ACL

```sh
acl modify --acl-id acl-12345678 --rule-file rules.acl
```

#### Delete a Network ACL

```sh
acl delete --acl-id acl-12345678
```

## ACL File Format

The `acl-file` format defines inbound and outbound rules for an AWS Network ACL. It is structured as follows:

### Sections

Each file consists of sections specifying inbound or outbound rules:

```
[inbound]
rule_number protocol port_range cidr_block action

[outbound]
rule_number protocol port_range cidr_block action
```

### Example ACL File

```
[inbound]
100 tcp 22 0.0.0.0/0 allow
200 tcp 80 0.0.0.0/0 allow

[outbound]
100 tcp 443 0.0.0.0/0 allow
```

## Contributing

1. Fork the repository.
2. Create a feature branch (`git checkout -b feature-name`).
3. Commit your changes (`git commit -m 'Add feature'`).
4. Push to the branch (`git push origin feature-name`).
5. Open a Pull Request.

## License

This project is licensed under the GPL 3 License.

---

For more details, see the man pages:
- `man acl` (General usage)
- `man acl-file` (File format reference)


