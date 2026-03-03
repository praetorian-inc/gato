# Fine-Grained PAT Support for Gato

**Date**: 2026-03-03
**Status**: Approved

## Problem

Gato explicitly rejects fine-grained PATs (`github_pat_` prefix) at `cli.py:111-114`. The entire permission model is built on classic PAT OAuth scopes (`repo`, `workflow`, `admin:org`) returned in the `x-oauth-scopes` response header. Fine-grained PATs don't return this header — they use 50+ granular permissions with no API endpoint for introspection.

Fine-grained PATs reached GA in March 2025 and are increasingly the default for GitHub organizations. Without support, Gato cannot be used with modern token configurations.

## Approach

**Unified Permission Abstraction** — Create a `TokenCapabilities` class that normalizes both classic scopes and fine-grained permissions into a unified capability model. All downstream code checks capabilities, not raw scopes.

For fine-grained PATs, permissions are discovered via **probe-based detection**: systematically test API endpoints and observe 200/403 responses to determine what the token can do.

## Architecture

### Token Detection

Replace `cli.py:111-119` rejection/validation logic:

```
github_pat_  → token_type = "fine_grained"
ghp_ / hex40 → token_type = "classic"
gho_ / ghu_  → token_type = "classic"
ghs_         → token_type = "app"
```

### TokenCapabilities Model

New file: `gato/models/token.py`

Properties (all boolean):

| Capability | Classic Scope Source | FG Permission Source |
|---|---|---|
| `can_read_contents` | `repo` | `contents:read` probe |
| `can_write_contents` | `repo` | `contents:write` probe |
| `can_read_actions` | `repo` | `actions:read` probe |
| `can_write_actions` | `workflow` | `actions:write` probe |
| `can_write_workflows` | `workflow` | `workflows:write` probe |
| `can_read_secrets` | `repo` | `secrets:read` probe |
| `can_admin_org` | `admin:org` | org admin detection |

Metadata: `token_type`, `user`, `name`, `expiration`, `raw_scopes`.

### Permission Probing Engine

New file: `gato/github/probe.py`

For fine-grained PATs only. Runs once at startup after token validation.

**Flow:**
1. Validate token via `GET /user`
2. Discover accessible repos via `GET /user/repos?affiliation=owner,collaborator,organization_member`
3. Select probe target (prefer private repo, fall back to public)
4. Run read probes (GET endpoints, 403 = no permission):

| Probe | Endpoint |
|---|---|
| `contents:read` | `GET /repos/{r}/commits` |
| `actions:read` | `GET /repos/{r}/actions/workflows` |
| `secrets:read` | `GET /repos/{r}/actions/secrets` |
| `administration:read` | `GET /repos/{r}/actions/permissions` |

5. Run write probes for detected read permissions:

| Probe | Method | Side Effect |
|---|---|---|
| `contents:write` | `POST /repos/{r}/git/blobs` | Dangling blob (invisible) |
| `actions:write` | `GET+PUT /repos/{r}/actions/oidc/customization/sub` | Re-sets same value |
| `workflows:write` | Create tree with `.github/workflows/testing` | Dangling tree (unreferenced) |

Total: ~13 API requests max.

### Downstream Changes

All 12+ scope check locations change from string matching to capability checks:

```python
# Before:
if 'repo' in self.user_perms['scopes'] and 'workflow' in self.user_perms['scopes']:

# After:
if self.capabilities.can_write_contents and self.capabilities.can_write_workflows:
```

### Attack Support

All three attack types are supported with fine-grained PATs:

| Attack | Required Capabilities | FG Permissions Needed |
|---|---|---|
| Shell workflow | `can_write_contents` + `can_write_workflows` | `contents:write` + `workflows:write` |
| Fork PR | `can_write_contents` + `can_write_workflows` | `contents:write` + `workflows:write` |
| Secrets dump | `can_write_contents` + `can_write_workflows` | `contents:write` + `workflows:write` |

Fork PR attack has a caveat: fine-grained PATs are scoped to specific repos, so forking may be limited. The tool will warn the user if the fork target is outside the token's repo scope.

### Fine-Grained PAT Limitations

1. **Org enumeration**: FG PATs see only repos granted to them. Self-enumeration uses `/user/repos` which returns all accessible repos. Org enumeration via `/orgs/{org}/repos` returns only repos in the token's scope.
2. **Org admin operations**: Require `organization_self_hosted_runners` and `organization_secrets` FG permissions. Probed at org level when attempting org enumeration.
3. **GraphQL**: Supported by FG PATs. Workflow YAML caching continues to work.
4. **Search**: Works without changes — just needs authenticated API access.

## Files Changed

### New Files

| File | Purpose |
|---|---|
| `gato/models/token.py` | `TokenCapabilities` class |
| `gato/github/probe.py` | Permission probing engine |

### Modified Files

| File | Changes |
|---|---|
| `gato/cli/cli.py` | Accept FG PATs, detect token type, construct capabilities |
| `gato/github/api.py` | `check_user()` handles FG response, add `is_fine_grained()` |
| `gato/enumerate/enumerate.py` | Use capabilities instead of scope strings |
| `gato/enumerate/organization.py` | Use `capabilities.can_admin_org` |
| `gato/enumerate/recommender.py` | Use capabilities throughout |
| `gato/attack/attack.py` | Use capabilities for permission gates |
| `gato/models/organization.py` | Accept `TokenCapabilities` instead of scope list |

## References

- [GitHub fine-grained PAT docs](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
- [Gato-X fine-grained implementation](https://adnanekhan.github.io/gato-x/user-guide/advanced/fine-grained-tokens/)
- [X-Accepted-GitHub-Permissions header](https://github.blog/changelog/2023-08-10-x-accepted-github-permissions-header-for-fine-grained-permission-actors/)
- [Fine-grained PATs GA announcement](https://github.blog/changelog/2025-03-18-fine-grained-pats-are-now-generally-available/)
