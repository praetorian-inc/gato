from gato.cli import Output
from gato.github.probe import PermissionProber
from gato.models.token import TokenCapabilities


def build_capabilities(api, user_perms: dict) -> TokenCapabilities:
    """Build TokenCapabilities from an API instance and user permissions dict.

    Handles both fine-grained PATs (via permission probing) and classic PATs
    (via OAuth scope headers). This centralises the logic previously duplicated
    across Enumerator, Attacker, and Searcher.

    Args:
        api: Authenticated ``Api`` instance (used to detect token type and
            perform probing for fine-grained PATs).
        user_perms: Dict returned by ``api.check_user()`` containing at least
            ``'user'``, ``'name'``, and ``'scopes'`` keys.

    Returns:
        A fully-populated ``TokenCapabilities`` object.
    """
    if api.is_fine_grained():
        prober = PermissionProber(api)
        repos = prober.discover_accessible_repos()

        if repos:
            probe_target = repos[0]
            is_private = probe_target.get("private", False)
            permissions = prober.run_all_probes(
                probe_target["full_name"], is_private
            )
        else:
            permissions = set()
            Output.warn(
                "No accessible repositories found for permission probing!"
            )

        caps = TokenCapabilities.from_fine_grained(
            user=user_perms['user'],
            name=user_perms.get('name', ''),
            permissions=permissions,
        )

        Output.info(f"Token type: {Output.bright('Fine-Grained PAT')}")
        Output.info(
            "Detected permissions: "
            f"{Output.yellow(caps.scope_summary())}"
        )
    else:
        caps = TokenCapabilities.from_classic_scopes(
            user=user_perms['user'],
            name=user_perms.get('name', ''),
            scopes=user_perms['scopes'],
        )

        if user_perms['scopes']:
            Output.info(
                "The GitHub Classic PAT has the following scopes: "
                f'{Output.yellow(", ".join(user_perms["scopes"]))}'
            )
        else:
            Output.warn("The token has no scopes!")

    return caps
