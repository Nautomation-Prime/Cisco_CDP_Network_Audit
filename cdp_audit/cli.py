"""Command line entry point for the CDP Network Audit tool."""

import logging
from concurrent.futures import ThreadPoolExecutor

from .app_config import config
from .credentials import CredentialManager
from .discovery import NetworkDiscoverer
from .excel_reporter import ExcelReporter
from .logging_setup import configure_logging
from .validators import normalize_seeds, validate_excel_template, validate_required_files

configure_logging()
logger = logging.getLogger(__name__)


def _prompt_for_jump_host() -> str:
    """Prompt for optional jump host selection.

    Returns:
        Jump host string (empty for direct connections).
    """
    default_jump = (config.JUMP_HOST or "").strip()

    use_jump_ans = input(
        f"\nUse jump host '{default_jump}'? [Y/n]\n"
        "Press Enter to accept the default shown. "
    ).strip().lower()

    use_jump = True if use_jump_ans in ("", "y", "yes") else False

    if not use_jump:
        logger.info("No jump server selected; connecting directly to devices.")
        return ""

    if default_jump:
        override = input(
            f"Press Enter to use '{default_jump}', or type a different jump host: "
        ).strip()
        jump_server = override if override else default_jump
    else:
        jump_server = input(
            "Enter jump server IP/hostname (leave blank to go direct): "
        ).strip()

    if jump_server:
        logger.info("Using jump server: %s", jump_server)
    else:
        logger.info("No jump server selected; connecting directly to devices.")

    return jump_server


def main() -> None:
    """Program entry point.

    Orchestrates validation, credential collection, discovery, and reporting.
    """
    limit = config.DEFAULT_LIMIT
    timeout = config.DEFAULT_TIMEOUT
    cdp_template = config.CDP_TEMPLATE
    ver_template = config.VER_TEMPLATE
    excel_template = config.EXCEL_TEMPLATE

    validate_required_files([cdp_template, ver_template, excel_template])
    validate_excel_template(excel_template)

    creds = CredentialManager()
    discoverer = NetworkDiscoverer(
        timeout=timeout,
        limit=limit,
        cdp_template=cdp_template,
        ver_template=ver_template,
    )
    reporter = ExcelReporter(excel_template)

    site_name, seeds, primary_user, primary_pass, answer_user, answer_pass = creds.prompt_for_inputs()

    jump_server = _prompt_for_jump_host()

    validated_seeds = normalize_seeds(seeds)
    logger.info("Validated %d seed device(s) for discovery", len(validated_seeds))

    for seed in validated_seeds:
        with discoverer.visited_lock:
            if seed in discoverer.visited or seed in discoverer.enqueued:
                continue
            discoverer.enqueued.add(seed)
            discoverer.host_queue.put(seed)

    with ThreadPoolExecutor(max_workers=limit) as executor:
        futures = [
            executor.submit(
                discoverer.discover_worker,
                jump_server,
                primary_user,
                primary_pass,
                answer_user,
                answer_pass,
            )
            for _ in range(limit)
        ]

        discoverer.host_queue.join()

        for _ in range(limit):
            discoverer.host_queue.put(None)

        discoverer.host_queue.join()

        for f in futures:
            f.result()

    discoverer.resolve_dns_parallel()

    reporter.save_to_excel(
        discoverer.cdp_neighbour_details,
        validated_seeds,
        site_name,
        discoverer.dns_ip,
        discoverer.authentication_errors,
        discoverer.connection_errors,
    )

    logger.info("Done!")
    logger.info(" Discovered devices: %d", len(discoverer.visited))
    logger.info(" CDP entries: %d", len(discoverer.cdp_neighbour_details))
    logger.info(" Auth errors: %d", len(discoverer.authentication_errors))
    logger.info(" Conn errors: %d", len(discoverer.connection_errors))
