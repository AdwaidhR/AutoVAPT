"""
Authorization Module
-----------------------
Hard ethical/legal gate. Every scan must pass through here before any
active module (ports, http, crawl, content discovery, vuln checks) runs.
This is deliberate friction, not a formality - do not remove it or make
it silently bypassable.
"""
import sys
from .utils import COLORS, log

WARNING_TEXT = f"""{COLORS['WARN']}{'=' * 60}
 AUTHORIZED SECURITY TESTING ONLY
{'=' * 60}{COLORS['END']}

 Only scan systems you own or have EXPLICIT WRITTEN PERMISSION
 to test. Unauthorized scanning is illegal in most jurisdictions
 (e.g. Computer Fraud and Abuse Act, UK Computer Misuse Act 1990,
 India IT Act 2000 Sections 43/66).

 This framework performs active reconnaissance, port scanning,
 web crawling, and content discovery against the target.
"""


def confirm_authorization(target, authorized_flag, non_interactive):
    """
    authorized_flag : True if --authorized or --yes was passed.
    non_interactive  : True if --non-interactive was passed (still
                        requires authorized_flag to be True - this flag
                        only controls whether we prompt, not whether we
                        require authorization at all).
    """
    print(WARNING_TEXT)
    print(f" Target: {target}\n")

    if not authorized_flag:
        if non_interactive:
            log("ERR", "Refusing to scan: --non-interactive requires --authorized/--yes too.")
            sys.exit(1)
        answer = input(" Continue? [y/N]: ").strip().lower()
        if answer != "y":
            log("ERR", "Authorization not confirmed. Exiting.")
            sys.exit(1)
        return True

    if non_interactive:
        log("WARN", "Running non-interactively with explicit authorization flag set.")
        return True

    answer = input(" Type 'I CONFIRM' to proceed: ").strip()
    if answer != "I CONFIRM":
        log("ERR", "Authorization not confirmed. Exiting.")
        sys.exit(1)
    return True
