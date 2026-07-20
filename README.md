# NiFi ACL Manager

A declarative access-control synchronizer for [Apache NiFi](https://nifi.apache.org/).

NiFi ACL Manager reads a JSON ACL definition, compares it with the users, groups, and access policies currently configured in NiFi, and applies the required changes through the NiFi REST API.

It supports:

- NiFi user synchronization
- NiFi user-group synchronization
- NiFi access-policy synchronization
- Mutual TLS authentication
- Dry-run previews
- Optional pruning of unmanaged resources
- Automatic preservation of permissions required by the manager
- NiFi cluster-node proxy permissions
- Optimistic locking through NiFi revision metadata

> **Warning**
>
> Pruning can delete NiFi users, groups, and policies that are not present in the desired ACL. Always run in dry-run mode and review the proposed changes before enabling pruning.

---

## How it works

The manager performs reconciliation in three stages:

1. Reads the current users, groups, and policies from NiFi.
2. Reads and validates the desired ACL from a JSON file.
3. Creates or updates resources whose current state differs from the desired state.

When pruning is enabled, resources not represented in the desired state are also removed.

Policy membership is compared using NiFi resource IDs rather than display names. User and group identities from the ACL are resolved to their corresponding NiFi IDs before policy requests are sent.

---

## Requirements

- Python 3.10 or newer
- Access to a secured NiFi REST API
- A client certificate and private key accepted by NiFi
- A NiFi user corresponding to the client certificate identity
- Sufficient NiFi permissions to manage:
  - Users and groups
  - Access policies
  - The flow policy
- A CA certificate when using a private certificate authority

Major Python dependencies include:

- `requests`
- `pydantic`
- `cryptography`

---

## Installation

Clone the repository:

```bash
git clone git@github.com:pnnl/nifi-manager.git
cd nifi-manager
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
uv sync
```

---

## Configuration

The manager expects configuration equivalent to the following fields:

| Setting | Description |
|---|---|
| `url` | Base URL of the NiFi API |
| `users_path` | NiFi users API path |
| `groups_path` | NiFi user-groups API path |
| `policies_path` | NiFi policies API path |
| `acl_file` | Path to the desired ACL JSON file |
| `cert_path` | Directory containing the client certificate |
| `certs` | Certificate and private-key pair passed to `requests` |
| `verify` | Whether TLS server verification is enabled |
| `ca_cert_path` | Optional path to a CA certificate or bundle |
| `dry_run` | Preview changes without modifying NiFi |
| `prune` | Delete managed resources absent from the ACL |
| `log_level` | Application logging level |

An illustrative configuration might look like:

```text
url=https://nifi.example.com/nifi-api
users_path=/tenants/users
groups_path=/tenants/user-groups
policies_path=/policies
acl_file=/etc/nifi-user-manager/acl.json
cert_path=/etc/nifi-user-manager/certs
verify=true
ca_cert_path=/etc/nifi-user-manager/certs/ca.crt
dry_run=true
prune=false
log_level=INFO
```

The exact file format or environment-variable names depend on the implementation in `config.py`.

---

## Mutual TLS authentication

The manager authenticates to NiFi using a client certificate.

The certificate directory is expected to contain:

```text
tls.crt
```

The certificate and private-key paths supplied through `config.certs` are passed to `requests`, typically as:

```python
("/path/to/tls.crt", "/path/to/tls.key")
```

The manager derives its NiFi identity from the certificate subject. The resulting identity must already exist as a NiFi user before the manager can run.

For example:

```text
CN=nifi-acl-manager, OU=PLATFORM
```

The exact distinguished-name format must match the identity recognized by NiFi and any configured NiFi identity-mapping rules.

---

## ACL file format

The ACL is a JSON document with three top-level collections:

```json
{
  "users": [],
  "groups": [],
  "policies": []
}
```

### Complete example

```json
{
  "users": [
    {
      "identity": "alice@example.com"
    },
    {
      "identity": "bob@example.com"
    },
    {
      "identity": "CN=nifi-node-1, OU=NIFI"
    }
  ],
  "groups": [
    {
      "identity": "data-engineers",
      "users": [
        "alice@example.com",
        "bob@example.com"
      ]
    },
    {
      "identity": "nifi-nodes",
      "users": [
        "CN=nifi-node-1, OU=NIFI"
      ]
    }
  ],
  "policies": [
    {
      "action": "read",
      "resource": "/flow",
      "users": [],
      "groups": [
        "data-engineers"
      ]
    },
    {
      "action": "read",
      "resource": "/process-groups/{root_pg_id}",
      "users": [],
      "groups": [
        "data-engineers"
      ]
    },
    {
      "action": "write",
      "resource": "/process-groups/{root_pg_id}",
      "users": [
        "alice@example.com"
      ],
      "groups": []
    }
  ]
}
```

---

## Users

Each desired user contains a NiFi identity:

```json
{
  "identity": "alice@example.com"
}
```

The identity must exactly match the identity expected by NiFi.

Certificate identities may look like:

```json
{
  "identity": "CN=nifi-node-1, OU=NIFI"
}
```

---

## Groups

Groups contain an identity and a collection of user identities:

```json
{
  "identity": "data-engineers",
  "users": [
    "alice@example.com",
    "bob@example.com"
  ]
}
```

Users referenced by groups should also appear in the desired user list.

During a normal run, the manager resolves each user identity to its NiFi user ID before creating or updating the group.

---

## Policies

A policy contains:

| Field | Description |
|---|---|
| `action` | Either `read` or `write` |
| `resource` | NiFi policy resource |
| `users` | User identities assigned directly to the policy |
| `groups` | Group identities assigned to the policy |

Example:

```json
{
  "action": "read",
  "resource": "/flow",
  "users": [
    "alice@example.com"
  ],
  "groups": [
    "data-engineers"
  ]
}
```

Policy resources are normalized to have exactly one leading slash. Both of the following therefore represent the same resource:

```json
"resource": "flow"
```

```json
"resource": "/flow"
```

Actions are restricted to:

```text
read
write
```

---

## Root process-group placeholder

The ACL may use the following placeholder in policy resources:

```text
{root_pg_id}
```

For example:

```json
{
  "action": "write",
  "resource": "/process-groups/{root_pg_id}",
  "users": [],
  "groups": [
    "data-engineers"
  ]
}
```

Before validating the ACL, the manager retrieves the root process-group ID from NiFi and replaces the placeholder.

This avoids hard-coding an environment-specific root process-group ID.

---

## Essential policies

The manager requires several permissions to continue operating safely. These include access to:

- The flow
- Tenants
- Policies

The authenticated manager user is retained on the required administrative policies.

Typical essential permissions include:

```text
read/flow
read/tenants
write/tenants
read/policies
write/policies
```

When NiFi cluster-node users are detected, they are also assigned to:

```text
write/proxy
```

Essential policies omitted from the ACL should be added to the effective desired state rather than pruned.

---

## Cluster users

Cluster users are detected from NiFi identities containing:

```text
OU=NIFI
```

The authenticated manager identity is excluded from this set.

Detected cluster users receive write access to the proxy resource, which is required for proxied requests between NiFi cluster nodes:

```text
write/proxy
```

If your NiFi node identities use a different naming convention, update the cluster-user detection logic or make it configurable.

---

## Running the manager

Run the application with:

```bash
python main.py
```

A typical dry-run invocation depends on how `config.py` loads configuration. For an environment-based configuration, it might resemble:

```bash
DRY_RUN=true \
PRUNE=false \
ACL_FILE=./acl.json \
python main.py
```

Refer to `config.py` for the authoritative setting names and loading behavior.

---

## Dry-run mode

Dry-run mode calculates and reports changes without submitting mutation requests to NiFi.

Enable it with:

```text
dry_run=true
```

Example output:

```text
running in DRY_RUN mode - no changes will be made
would create policy read on /flow
would update policy write on /process-groups/abc123
would delete policy read on /counters
```

Dry-run mode should always be used before enabling pruning.

### Dry-run member IDs

New users and groups do not yet have NiFi IDs in dry-run mode. The manager may use their identities as temporary placeholders while calculating policy changes. These placeholders must never be sent to NiFi in a non-dry-run request.

---

## Pruning

Pruning removes resources that exist in NiFi but are absent from the effective desired state.

Enable it with:

```text
prune=true
```

When enabled, the manager can remove:

- Users absent from the desired user list
- Groups absent from the desired group list
- Policies absent from the effective desired policy list

### Recommended deletion order

To avoid deleting resources while they are still referenced, reconciliation should use the following order:

1. Create or update users
2. Create or update groups
3. Create or update policies
4. Delete obsolete policies
5. Delete obsolete groups
6. Delete obsolete users

The authenticated manager user and NiFi cluster-node users should be protected from pruning.

> **Important**
>
> Do not enable pruning until dry-run output has been reviewed. An incomplete ACL can otherwise remove valid NiFi access.

---

## Managed policy resources

The policy service manages a defined set of NiFi resources, including:

- Flow
- Tenants
- Policies
- Controller
- Proxy
- Restricted components
- Provenance
- Site-to-site
- System
- Counters
- Root process group

Restricted-component resources include:

```text
/restricted-components
/restricted-components/access-environment-credentials
/restricted-components/access-keytab
/restricted-components/access-ticket-cache
/restricted-components/execute-code
/restricted-components/export-nifi-details
/restricted-components/read-distributed-filesystem
/restricted-components/read-filesystem
/restricted-components/reference-remote-resources
/restricted-components/write-distributed-filesystem
/restricted-components/write-filesystem
```

The current implementation queries a predefined list rather than dynamically discovering every possible NiFi policy resource. Add newly supported resources to the managed policy list as needed.

---

## Change reporting

Changes are represented as one of:

```text
ADDED
UPDATED
REMOVED
```

Examples:

```text
ADDED    User: alice@example.com
UPDATED  Group: data-engineers, Members: ['alice@example.com']
REMOVED  Policy: read on /counters, Members: Users: [], Groups: []
```

At the end of a successful run, the application logs either:

- The changes that were made
- That no changes were required

Failures are collected during reconciliation so independent resources can continue processing where possible.

---

## Error handling

The manager defines resource-specific failures for common conditions such as:

- Authenticated NiFi user not found
- Referenced user not found
- Referenced group not found
- Health check failure
- Policy creation failure
- Policy conflict
- Policy lookup failure
- Policy update failure
- Policy deletion failure

HTTP response failures are raised by `requests` through `raise_for_status()` and translated into service-specific exceptions where appropriate.

For production automation, the application should exit with a nonzero status whenever reconciliation failures are collected.

---

## Project structure

A typical project layout is:

```text
.
├── main.py
├── manager.py
├── config.py
├── methods.py
├── models/
│   ├── __init__.py
│   ├── nifi_models.py
│   └── ...
├── services/
│   ├── users.py
│   ├── groups.py
│   ├── policies.py
│   └── process_groups.py
├── requirements.txt
└── README.md
```

### Components

#### `main.py`

- Loads configuration
- Configures logging
- Runs the manager
- Reports changes and failures

#### `manager.py`

- Loads observed NiFi state
- Reads the desired ACL
- Resolves user and group membership
- Coordinates synchronization and pruning
- Preserves required administrative access

#### `services/users.py`

- Reads NiFi users
- Creates or updates users
- Deletes unmanaged users

#### `services/groups.py`

- Reads NiFi user groups
- Creates or updates group membership
- Deletes unmanaged groups

#### `services/policies.py`

- Reads managed NiFi access policies
- Creates or updates policy membership
- Deletes unmanaged policies
- Normalizes policy permission keys

#### `methods.py`

- Wraps HTTP operations
- Configures client certificates and TLS verification
- Raises on unsuccessful HTTP responses
- Implements the NiFi health check

#### `models/`

- Validates NiFi API responses
- Validates ACL input
- Normalizes policy resources
- Defines change-reporting models

---

## Security considerations

### Protect the manager identity

The certificate identity used by the manager must not be deleted or stripped of required permissions. Protect it explicitly during user pruning and policy reconciliation.

### Protect NiFi node identities

Cluster-node users should not be removed by pruning. They require proxy permission for normal cluster operation.

### Restrict certificate access

The client private key grants access to NiFi. Store it with restrictive file permissions:

```bash
chmod 600 /path/to/tls.key
```

### Keep TLS verification enabled

Production configuration should use:

```text
verify=true
```

and either the operating system trust store or an explicit CA bundle.

Avoid disabling certificate verification except during isolated development.

### Review prune output

Treat dry-run output as a deployment approval artifact. Review all removals before running with prune enabled.

---

## Example reconciliation

Given this desired policy:

```json
{
  "action": "read",
  "resource": "/flow",
  "users": [
    "alice@example.com"
  ],
  "groups": []
}
```

and an existing NiFi policy containing only:

```text
bob@example.com
```

the manager:

1. Resolves `alice@example.com` to its NiFi user ID.
2. Adds the authenticated manager user if required for the policy.
3. Compares the desired member-ID set with the existing set.
4. Sends an update using the current NiFi revision version.
5. Records an `UPDATED` policy change.

If the sets already match, no request is made.

---

## Troubleshooting

### Authenticated user not found

Example:

```text
User CN=nifi-acl-manager, OU=PLATFORM not found
```

Verify that:

- The certificate subject matches the identity known to NiFi.
- NiFi identity-mapping rules do not transform the identity unexpectedly.
- The user was provisioned before running the manager.

### Referenced user not found

Example:

```text
could not find alice@example.com in user list
```

Ensure that the user:

- Appears in the ACL user list
- Was created successfully
- Uses the exact identity expected by NiFi

### Referenced group not found

Example:

```text
could not find data-engineers in group list
```

Ensure that the group appears in the ACL and was synchronized before policies.

### Policy already exists

A `409 Conflict` during creation usually means the policy exists but was not discovered in the manager’s predefined policy-resource list.

Add the resource to the managed policy list or use a NiFi endpoint capable of listing all policies.

### Optimistic-lock conflict

NiFi policies use revision versions. A concurrent update may cause a conflict if the revision changes between retrieval and update.

Re-run reconciliation after confirming that no other manager is modifying the same resources.

### Excessive missing-policy warnings

The manager queries a predefined set of possible policy resources. Missing policies may be normal. Consider logging expected `404` responses at debug level rather than warning level.

---

## Operational recommendations

- Start with `dry_run=true`.
- Keep `prune=false` during initial deployment.
- Review every proposed deletion.
- Run only one manager instance at a time.
- Protect the authenticated and cluster-node users.
- Back up NiFi authorization configuration before first use.
- Monitor and alert on collected reconciliation failures.
- Return a nonzero process exit status when any operation fails.
- Use request timeouts to prevent indefinitely hanging API calls.

