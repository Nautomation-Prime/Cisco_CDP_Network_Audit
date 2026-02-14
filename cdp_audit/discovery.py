"""Network discovery logic."""

import logging
import queue
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Tuple

import paramiko
import textfsm
from netmiko import ConnectHandler

try:
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException  # type: ignore

from paramiko.ssh_exception import SSHException

from .app_config import config

logger = logging.getLogger(__name__)


class NetworkDiscoverer:
    """
    Coordinate threaded discovery via Netmiko, parse outputs via TextFSM, and
    accumulate results for reporting.
    """

    def __init__(self, timeout: int, limit: int, cdp_template: Path, ver_template: Path) -> None:
        self.timeout = timeout
        self.limit = limit
        self.cdp_template = cdp_template
        self.ver_template = ver_template

        self.cdp_neighbour_details: List[Dict] = []
        self.hostnames: set = set()
        self.visited: set = set()
        self.enqueued: set = set()
        self.visited_hostnames: set = set()
        self.authentication_errors: set = set()
        self.connection_errors: Dict[str, str] = {}
        self.dns_ip: Dict[str, str] = {}

        self.visited_lock = threading.Lock()
        self.data_lock = threading.Lock()
        self.host_queue: "queue.Queue[str]" = queue.Queue()

    def _safe_parse_textfsm(self, template_path: Path, text: str) -> List[Dict]:
        """Parse text using a TextFSM template, returning an empty list on failure."""
        try:
            with open(template_path, "r", encoding="cp1252") as f:
                table = textfsm.TextFSM(f)
                rows = table.ParseText(text or "")
                return [dict(zip(table.header, row)) for row in rows]
        except (OSError, textfsm.TextFSMError) as exc:
            logger.debug("TextFSM parse failed for %s: %s", template_path, exc, exc_info=True)
            return []
        except Exception:
            logger.exception("Unexpected error while parsing template %s", template_path)
            return []

    def parse_outputs_and_enqueue_neighbors(self, host: str, cdp_output, version_output: str) -> None:
        """Enrich parsed rows, append to dataset, and enqueue neighbors by management IP.

        Args:
            host: The device IP address being processed.
            cdp_output: Raw CDP output string or a pre-parsed list of dict rows.
            version_output: Raw ``show version`` output string.
        """
        ver_list = self._safe_parse_textfsm(self.ver_template, version_output)
        if ver_list:
            hostname = ver_list[0].get("HOSTNAME", host)
            serial_numbers = ver_list[0].get("SERIAL", "")
            uptime = ver_list[0].get("UPTIME", "")
        else:
            hostname, serial_numbers, uptime = host, "", ""

        with self.data_lock:
            if hostname:
                self.hostnames.add(hostname)
                self.visited_hostnames.add(hostname)
        with self.visited_lock:
            self.visited.add(host)

        if isinstance(cdp_output, list):
            rows = cdp_output
        else:
            rows = self._safe_parse_textfsm(self.cdp_template, cdp_output)

        for entry in rows:
            raw_name = entry.get("DESTINATION_HOST") or entry.get("DEVICE_ID") or ""
            head = raw_name.split(".", 1)[0].upper() if raw_name else ""
            entry["DESTINATION_HOST"] = head

            entry["LOCAL_HOST"] = hostname
            entry["LOCAL_IP"] = host
            entry["LOCAL_SERIAL"] = serial_numbers
            entry["LOCAL_UPTIME"] = uptime

            mgmt_ip = (
                entry.get("MANAGEMENT_IP") or entry.get("NEIGHBOR_IP") or entry.get("IP") or ""
            ).strip()
            entry["MANAGEMENT_IP"] = mgmt_ip
            caps = entry.get("CAPABILITIES", "")

            with self.data_lock:
                self.cdp_neighbour_details.append(entry)

            if mgmt_ip:
                should_enqueue = False
                with self.visited_lock:
                    if (
                        mgmt_ip not in self.visited
                        and mgmt_ip not in self.enqueued
                        and "Host" not in caps
                        and "Switch" in caps
                    ):
                        self.enqueued.add(mgmt_ip)
                        should_enqueue = True
                if should_enqueue:
                    logger.debug("Enqueuing neighbor %s (%s) discovered from %s", head, mgmt_ip, host)
                    self.host_queue.put(mgmt_ip)

    def _paramiko_jump_client(self, jump_host: str, username: str, password: str) -> paramiko.SSHClient:
        """Establish an SSH client to the jump host using password auth."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.WarningPolicy())
        client.connect(
            hostname=jump_host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=self.timeout,
            auth_timeout=self.timeout,
            timeout=self.timeout,
            channel_timeout=self.timeout,
        )
        try:
            transport = client.get_transport()
            if transport and transport.sock:
                transport.sock.settimeout(self.timeout)
                logger.debug("Set socket timeout to %d seconds for jump host %s", self.timeout, jump_host)
        except Exception as exc:
            logger.debug("Could not set socket timeout on jump client: %s", exc)
        return client

    def _netmiko_via_jump(
        self,
        jump_host: str,
        target_ip: str,
        primary: bool,
        primary_user: str,
        primary_pass: str,
        answer_user: str,
        answer_pass: str,
    ):
        """Create a Netmiko connection, optionally tunneled through a jump host."""
        if primary:
            j_user, j_pass = primary_user, primary_pass
            d_user, d_pass = primary_user, primary_pass
        else:
            j_user, j_pass = primary_user, primary_pass
            d_user, d_pass = answer_user, answer_pass

        if not jump_host:
            return ConnectHandler(
                device_type=config.DEVICE_TYPE,
                host=target_ip,
                username=d_user,
                password=d_pass,
                fast_cli=False,
                timeout=self.timeout,
                conn_timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )

        jump = None
        try:
            jump = self._paramiko_jump_client(jump_host, j_user, j_pass)
            transport = jump.get_transport()
            dest_addr = (target_ip, config.SSH_PORT)
            local_addr = ("127.0.0.1", 0)
            channel = transport.open_channel("direct-tcpip", dest_addr, local_addr, timeout=self.timeout)
            logger.debug("[%s] Jump channel opened via %s", target_ip, jump_host)

            conn = ConnectHandler(
                device_type=config.DEVICE_TYPE,
                host=target_ip,
                username=d_user,
                password=d_pass,
                sock=channel,
                fast_cli=False,
                timeout=self.timeout,
                conn_timeout=self.timeout,
                banner_timeout=self.timeout,
                auth_timeout=self.timeout,
            )

            conn._jump_client = jump  # type: ignore[attr-defined]
            return conn
        except Exception:
            if jump is not None:
                try:
                    jump.close()
                except Exception:
                    logger.debug("Failed to close jump client after error.", exc_info=True)
            raise

    def _parse_cdp_entry_star_blocks(self, proto_text: str, vers_text: str):
        """Parse entry* protocol/version outputs into normalized dict rows.

        This is used when ``show cdp neighbors detail`` appears truncated and the
        tool falls back to collecting per-neighbor blocks instead.
        """
        import re

        def split_blocks(raw: str) -> dict:
            blocks = {}
            parts = re.split(r"\n(?=Device ID:\s*)", raw or "", flags=re.IGNORECASE)
            for part in parts:
                if not part.strip():
                    continue
                match = re.search(r"Device ID:\s*(.+)", part, flags=re.IGNORECASE)
                if match:
                    dev = match.group(1).strip()
                    blocks[dev] = part
            return blocks

        proto_blocks = split_blocks(proto_text)
        vers_blocks = split_blocks(vers_text)
        all_ids = set(proto_blocks) | set(vers_blocks)

        rows = []
        for dev_id in sorted(all_ids):
            pblk = proto_blocks.get(dev_id, "")
            vblk = vers_blocks.get(dev_id, "")

            def grab(pattern, text, flags=re.IGNORECASE | re.DOTALL):
                match = re.search(pattern, text or "", flags)
                return match.group(1).strip() if match else ""

            mgmt_ip = grab(r"IP address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", pblk) or grab(
                r"IP address:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)", vblk
            )
            platform = grab(r"Platform:\s*([^,]+)", vblk)
            caps = grab(r"Capabilities:\s*([^\n]+)", vblk)
            local_if = grab(r"Interface:\s*([^\s,]+)", pblk)
            remote_if = grab(r"Port ID\s*\(outgoing port\):\s*([^\s,]+)", pblk)

            rows.append(
                {
                    "DESTINATION_HOST": (dev_id.split(".", 1)[0].upper() if dev_id else ""),
                    "MANAGEMENT_IP": mgmt_ip,
                    "PLATFORM": platform,
                    "CAPABILITIES": caps,
                    "LOCAL_PORT": local_if,
                    "REMOTE_PORT": remote_if,
                }
            )
        return rows

    def run_device_commands(
        self,
        jump_host: str,
        host: str,
        primary_user: str,
        primary_pass: str,
        answer_user: str,
        answer_pass: str,
    ):
        """Run CDP and version commands using a tiered fallback strategy.

        Returns:
            A tuple of (cdp_output, version_output). The CDP element may be the
            raw output string or a list of parsed rows when the entry* fallback
            is used.
        """

        def prep(conn) -> None:
            try:
                conn.enable()
            except Exception:
                pass
            try:
                conn.global_cmd_verify = False
            except Exception:
                pass
            for cmd in ("terminal length 0", "terminal width 512", "no logging console"):
                try:
                    conn.send_command(cmd, expect_string=r"#", read_timeout=self.timeout)
                except Exception:
                    pass
            time.sleep(0.5)

        def connect(primary: bool):
            return self._netmiko_via_jump(
                jump_host=jump_host,
                target_ip=host,
                primary=primary,
                primary_user=primary_user,
                primary_pass=primary_pass,
                answer_user=answer_user,
                answer_pass=answer_pass,
            )

        conn = None
        try:
            try:
                conn = connect(True)
                logger.info("%s Netmiko connected (primary creds)%s", host, " via jump" if jump_host else "")
            except NetmikoAuthenticationException:
                conn = connect(False)
                logger.info(
                    "%s Netmiko connected (fallback 'answer' creds)%s",
                    host,
                    " via jump" if jump_host else "",
                )

            prep(conn)

            try:
                conn.clear_buffer()
            except Exception:
                pass

            detail = conn.send_command_timing(
                "show cdp neighbors detail",
                delay_factor=4,
                read_timeout=max(self.timeout, 60),
                strip_prompt=False,
                strip_command=False,
            )
            time.sleep(2)
            detail += conn.read_channel()
            logger.debug("=== RAW CDP OUTPUT FROM %s ===\n%s\n=== END RAW CDP ===", host, detail)
            device_id_count = detail.count("Device ID:")
            looks_truncated = (device_id_count == 0) or (len(detail) < 1000)

            try:
                summary = conn.send_command(
                    "show cdp neighbors",
                    expect_string=r"#",
                    read_timeout=max(self.timeout, 20),
                    delay_factor=2,
                    strip_prompt=False,
                    strip_command=False,
                )
                summary_count = sum(
                    1
                    for ln in summary.splitlines()
                    if ln.strip() and not ln.startswith(("Device ID", "Capability", "-----"))
                )
                if 0 < device_id_count < summary_count:
                    looks_truncated = True
            except Exception:
                pass

            if not looks_truncated:
                ver = conn.send_command("show version", expect_string=r"#", read_timeout=max(self.timeout, 20))
                return detail, ver

            logger.debug(
                "[%s] CDP detail seems truncated (Device ID count: %d). Falling back to entry*.",
                host,
                device_id_count,
            )

            proto = conn.send_command(
                "show cdp entry * protocol",
                expect_string=r"#",
                read_timeout=max(self.timeout, 45),
                delay_factor=4,
                strip_prompt=False,
                strip_command=False,
            )
            vers = conn.send_command(
                "show cdp entry * version",
                expect_string=r"#",
                read_timeout=max(self.timeout, 45),
                delay_factor=4,
                strip_prompt=False,
                strip_command=False,
            )
            rows = self._parse_cdp_entry_star_blocks(proto, vers)
            ver = conn.send_command("show version", expect_string=r"#", read_timeout=max(self.timeout, 20))
            if rows:
                return rows, ver

            ver = conn.send_command("show version", expect_string=r"#", read_timeout=max(self.timeout, 20))
            return detail, ver

        finally:
            try:
                if conn:
                    conn.disconnect()
            except Exception:
                logger.debug("Error disconnecting Netmiko connection", exc_info=True)
            try:
                if conn and hasattr(conn, "_jump_client") and conn._jump_client:
                    conn._jump_client.close()
            except Exception:
                logger.debug("Error closing jump client after disconnect", exc_info=True)

    def discover_worker(self, jump_host, primary_user, primary_pass, answer_user, answer_pass) -> None:
        """Worker thread for parallel device discovery.

        Each worker dequeues targets, attempts authentication with primary creds
        first, falls back to the ``answer`` account if needed, and records errors
        for reporting.
        """
        tname = threading.current_thread().name
        logger.info("Worker start: %s", tname)
        try:
            while True:
                item = None
                try:
                    item = self.host_queue.get(timeout=1.0)
                except queue.Empty:
                    time.sleep(0.2)
                    continue

                try:
                    if item is None:
                        logger.info("Worker exit (sentinel): %s", tname)
                        return

                    host = item

                    with self.visited_lock:
                        self.enqueued.discard(host)

                    if host in self.visited:
                        continue

                    last_err = None
                    for attempt in range(1, config.MAX_RETRY_ATTEMPTS + 1):
                        logger.info("[%s] %s Attempt %d: collecting CDP + version", host, tname, attempt)
                        try:
                            cdp_out, ver_out = self.run_device_commands(
                                jump_host,
                                host,
                                primary_user,
                                primary_pass,
                                answer_user,
                                answer_pass,
                            )
                            self.parse_outputs_and_enqueue_neighbors(host, cdp_out, ver_out)
                            logger.info("%s Discovery successful", host)
                            last_err = None
                            break
                        except NetmikoAuthenticationException:
                            logger.info("[%s] Authentication failed", host)
                            with self.data_lock:
                                self.authentication_errors.add(host)
                            last_err = None
                            break
                        except (NetmikoTimeoutException, SSHException, socket.timeout) as exc:
                            logger.warning("[%s] Connection issue (attempt %d): %s", host, attempt, exc)
                            last_err = type(exc).__name__
                        except Exception:
                            logger.exception("[%s] Unexpected error (attempt %d)", host, attempt)
                            last_err = "UnexpectedError"

                    with self.visited_lock:
                        self.visited.add(host)
                    if last_err:
                        with self.data_lock:
                            self.connection_errors.setdefault(host, last_err)

                except Exception:
                    logger.exception("Unexpected error processing item: %s", item)
                finally:
                    self.host_queue.task_done()

        except Exception:
            logger.exception("Worker thread crashed: %s", tname)

    def resolve_dns_for_host(self, hname: str) -> Tuple[str, str]:
        """Resolve a single hostname to IPv4 address (best-effort)."""
        try:
            logger.debug("[DNS] Resolving %s", hname)
            ip = socket.gethostbyname(hname)
            logger.debug("[DNS] %s resolved to %s", hname, ip)
            return hname, ip
        except socket.gaierror as exc:
            logger.debug("[DNS] Failed to resolve %s: %s", hname, exc.strerror)
            return hname, config.DNS_UNRESOLVED_MARKER
        except Exception:
            logger.exception("[DNS] Unexpected error resolving %s", hname)
            return hname, config.DNS_ERROR_MARKER

    def resolve_dns_parallel(self) -> None:
        """Resolve collected hostnames using a bounded thread pool."""
        names = list(self.hostnames)
        results: List[Tuple[str, str]] = []
        if not names:
            return
        with ThreadPoolExecutor(
            max_workers=min(config.DNS_MAX_WORKERS, max(config.DNS_MIN_WORKERS, self.limit))
        ) as ex:
            futs = [ex.submit(self.resolve_dns_for_host, n) for n in names]
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception:
                    logger.exception("DNS worker failed while resolving names")
        with self.data_lock:
            for h, ip in results:
                self.dns_ip[h] = ip
