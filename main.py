#!/usr/bin/env python3
# -*- coding: cp1252 -*-

import os
import sys
import threading
import queue
import socket
import shutil
import datetime
import ipaddress
import logging
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional, Tuple, List, Dict

import pandas as pd
import openpyxl
import textfsm
import paramiko
from netmiko import ConnectHandler
try:
    from netmiko.exceptions import NetmikoAuthenticationException, NetmikoTimeoutException
except ImportError:
    from netmiko.ssh_exception import NetmikoAuthenticationException, NetmikoTimeoutException

from paramiko.ssh_exception import SSHException
from ProgramFiles import config_params  # reads ProgramFiles/config_files/global_config.ini

# Configure logging (use INFO default; can be raised to DEBUG for more detail)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)


class ConfigLoader:
    def __init__(self):
        self.limit = int(config_params.Settings["LIMIT"])
        self.timeout = int(config_params.Settings["TIMEOUT"])
        self.jump_server = config_params.Jump_Servers["ACTIVE"]
        self.base_dir = Path(".")
        self.cdp_template = self.base_dir / "ProgramFiles" / "textfsm" / "cisco_ios_show_cdp_neighbors_detail.textfsm"
        self.ver_template = self.base_dir / "ProgramFiles" / "textfsm" / "cisco_ios_show_version.textfsm"
        self.excel_template = self.base_dir / "ProgramFiles" / "config_files" / "1 - CDP Network Audit _ Template.xlsx"

        # Validate templates and excel template early to fail fast
        missing = []
        for p in (self.cdp_template, self.ver_template, self.excel_template):
            if not p.exists():
                missing.append(str(p))
        if missing:
            raise FileNotFoundError(f"Required files missing: {', '.join(missing)}")


class CredentialManager:
    def __init__(self):
        self.primary_target = os.getenv("CDP_PRIMARY_CRED_TARGET", "MyApp/ADM")
        self.answer_target = os.getenv("CDP_ANSWER_CRED_TARGET", "MyApp/Answer")

    def _read_win_cred(self, target_name: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            if not sys.platform.startswith("win"):
                return None, None
            import win32cred  # type: ignore
            cred = win32cred.CredRead(target_name, win32cred.CRED_TYPE_GENERIC)  # type: ignore
            user = cred.get("UserName")
            blob = cred.get("CredentialBlob")
            pwd = blob.decode("utf-16le") if blob else None
            if user and pwd:
                return user, pwd
        except Exception:
            logger.debug("Reading credentials from Windows Credential Manager failed.", exc_info=True)
        return None, None

    def _write_win_cred(self, target: str, username: str, password: str, persist: int = 2) -> bool:
        try:
            if not sys.platform.startswith("win"):
                logger.warning("Not a Windows platform; cannot store credentials in Credential Manager.")
                return False
            import win32cred  # type: ignore
            blob = password.encode("utf-16le")
            credential = {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": target,
                "UserName": username,
                "CredentialBlob": blob,
                "Comment": "Created by CDP Network Audit tool",
                "Persist": persist,
                "AttributeCount": 0,
                "Attributes": None,
            }
            win32cred.CredWrite(credential, 0)
            logger.info("Stored/updated credentials in Windows Credential Manager: %s", target)
            return True
        except Exception:
            logger.exception("Failed to write credentials for '%s'", target)
            return False

    def _prompt_yes_no(self, msg: str, default_no: bool = True) -> bool:
        suffix = " [y/N] " if default_no else " [Y/n] "
        ans = input(msg + suffix).strip().lower()
        if ans == "":
            return not default_no
        return ans in ("y", "yes")

    def get_secret_with_fallback(self, display_name: str, cred_target: Optional[str] = None,
                                 prompt_user: Optional[str] = None, prompt_pass: Optional[str] = None,
                                 fixed_username: Optional[str] = None) -> Tuple[str, str]:
        if cred_target and sys.platform.startswith("win"):
            u, p = self._read_win_cred(cred_target)
            if u and p:
                if fixed_username and fixed_username.lower() != u.lower():
                    logger.info("Loaded %s password from CredMan (%s). Using fixed username '%s'.", display_name, cred_target, fixed_username)
                    return fixed_username, p
                logger.info("Loaded %s credentials from Windows Credential Manager (%s).", display_name, cred_target)
                return (fixed_username or u), p
        import getpass
        if fixed_username:
            user = fixed_username
            if not prompt_pass:
                prompt_pass = f"Enter {display_name} password: "
            pwd = getpass.getpass(prompt_pass)
            if not pwd:
                raise RuntimeError(f"{display_name} password not provided.")
            return user, pwd
        if not prompt_user:
            prompt_user = f"Enter {display_name} username: "
        if not prompt_pass:
            prompt_pass = f"Enter {display_name} password: "
        user = input(prompt_user).strip()
        pwd = getpass.getpass(prompt_pass)
        if not user or not pwd:
            raise RuntimeError(f"{display_name} credentials not provided.")
        return user, pwd

    def prompt_for_inputs(self):
        logger.info("=== CDP Network Audit ===")
        site_name = input("Enter site name (used in Excel filename): ").strip()
        while not site_name:
            site_name = input("Site name cannot be empty. Please enter site name: ").strip()
        seed_str = input("Enter one or more seed device IPs or hostnames (comma-separated): ").strip()
        while not seed_str:
            seed_str = input("Seed IPs cannot be empty. Please enter one or more IPs: ").strip()
        seeds = [s.strip() for s in seed_str.split(",") if s.strip()]

        # Primary credentials
        stored_user, stored_pass = self._read_win_cred(self.primary_target) if sys.platform.startswith("win") else (None, None)
        if stored_user and stored_pass:
            logger.info("Found stored Primary user: %s (target: %s)", stored_user, self.primary_target)
            override = input("Press Enter to accept, or type a different username: ").strip()
            if override:
                import getpass
                primary_user = override
                primary_pass = getpass.getpass("Enter switch/jump password (Primary): ")
                if self._prompt_yes_no(f"Save these Primary creds to Credential Manager as '{self.primary_target}'?", default_no=True):
                    self._write_win_cred(self.primary_target, primary_user, primary_pass)
            else:
                primary_user, primary_pass = stored_user, stored_pass
        else:
            primary_user, primary_pass = self.get_secret_with_fallback(
                display_name="Primary (jump/device)",
                cred_target=None,
                prompt_user="Enter switch/jump username (Primary): ",
                prompt_pass="Enter switch/jump password (Primary): ",
            )
            if self._prompt_yes_no(f"Store Primary creds in Credential Manager as '{self.primary_target}'?", default_no=True):
                self._write_win_cred(self.primary_target, primary_user, primary_pass)

        # Answer credentials
        answer_user = "answer"
        a_user, a_pass = self._read_win_cred(self.answer_target) if sys.platform.startswith("win") else (None, None)
        if a_user and a_pass:
            logger.info("Loaded Answer password from Credential Manager (%s). Username fixed to 'answer'.", self.answer_target)
            answer_pass = a_pass
        else:
            _, answer_pass = self.get_secret_with_fallback(
                display_name="Answer (device fallback)",
                cred_target=None,
                prompt_user=None,
                prompt_pass="Enter 'answer' password: ",
                fixed_username="answer",
            )
            if self._prompt_yes_no(f"Store 'answer' password in Credential Manager as '{self.answer_target}'?", default_no=True):
                self._write_win_cred(self.answer_target, answer_user, answer_pass)

        return site_name, seeds, primary_user, primary_pass, answer_user, answer_pass


class ExcelReporter:
    def __init__(self, excel_template):
        self.excel_template = excel_template

    def save_to_excel(self, details_list, hosts, site_name, dns_ip, auth_errors, conn_errors):
        df = pd.DataFrame(details_list, columns=[
            "LOCAL_HOST", "LOCAL_IP", "LOCAL_PORT", "LOCAL_SERIAL", "LOCAL_UPTIME",
            "DESTINATION_HOST", "REMOTE_PORT", "MANAGEMENT_IP", "PLATFORM",
        ])
        dns_array = pd.DataFrame(dns_ip.items(), columns=["Hostname", "IP Address"])
        auth_array = pd.DataFrame(sorted(list(auth_errors)), columns=["Authentication Errors"])
        conn_array = pd.DataFrame(conn_errors.items(), columns=["IP Address", "Error"])
        filepath = f"{site_name}_CDP_Network_Audit.xlsx"
        shutil.copy2(src=self.excel_template, dst=filepath)
        date_now = datetime.datetime.now().strftime("%d %B %Y")
        time_now = datetime.datetime.now().strftime("%H:%M")
        wb = openpyxl.load_workbook(filepath)
        ws1 = wb["Audit"]
        ws1["B4"] = site_name
        ws1["B5"] = date_now
        ws1["B6"] = time_now
        ws1["B7"] = hosts[0] if hosts else ""
        ws1["B8"] = hosts[1] if len(hosts) > 1 else "Secondary Seed device not given"
        wb.save(filepath)
        wb.close()
        with pd.ExcelWriter(filepath, engine="openpyxl", if_sheet_exists="overlay", mode="a") as writer:
            df.to_excel(writer, index=False, sheet_name="Audit", header=False, startrow=11)
            dns_array.to_excel(writer, index=False, sheet_name="DNS Resolved", header=False, startrow=4)
            auth_array.to_excel(writer, index=False, sheet_name="Authentication Errors", header=False, startrow=4)
            conn_array.to_excel(writer, index=False, sheet_name="Connection Errors", header=False, startrow=4)


class NetworkDiscoverer:
    def __init__(self, config: ConfigLoader):
        self.config = config
        self.cdp_neighbour_details: List[Dict] = []
        self.hostnames: set = set()
        self.visited: set = set()
        self.visited_hostnames: set = set()
        self.authentication_errors: set = set()
        self.connection_errors: Dict[str, str] = {}
        self.dns_ip: Dict[str, str] = {}
        self.visited_lock = threading.Lock()
        self.data_lock = threading.Lock()
        self.host_queue: "queue.Queue[str]" = queue.Queue()

    def _safe_parse_textfsm(self, template_path: Path, text: str) -> List[Dict]:
        """
        Helper to parse text with TextFSM, returning list of dicts.
        If parsing fails, returns empty list and logs a debug message.
        """
        try:
            with open(template_path, "r", encoding="cp1252") as f:
                table = textfsm.TextFSM(f)
                rows = table.ParseText(text or "")
                return [dict(zip(table.header, row)) for row in rows]
        except (OSError, textfsm.TextFSMError) as e:
            logger.debug("TextFSM parse failed for %s: %s", template_path, e, exc_info=True)
            return []
        except Exception:
            logger.exception("Unexpected error while parsing template %s", template_path)
            return []

    def parse_outputs_and_enqueue_neighbors(self, host: str, cdp_output: str, version_output: str):
        """
        Robust parsing + normalization of CDP and version outputs.
        - Normalizes DESTINATION_HOST to head-only, uppercase.
        - Adds LOCAL_* fields.
        - Records hostname/serial/uptime.
        - Enqueues switch management IPs only once (marks as visited when enqueued).
        """
        cdp_list = self._safe_parse_textfsm(self.config.cdp_template, cdp_output)
        ver_list = self._safe_parse_textfsm(self.config.ver_template, version_output)

        if ver_list:
            hostname = ver_list[0].get("HOSTNAME", host)
            serial_numbers = ver_list[0].get("SERIAL", "")
            uptime = ver_list[0].get("UPTIME", "")
        else:
            hostname = host
            serial_numbers = ""
            uptime = ""

        # Register hostname (data structures) once
        with self.data_lock:
            if hostname:
                self.hostnames.add(hostname)
                self.visited_hostnames.add(hostname)

        # Mark the current IP as visited (we have processed or are processing it)
        with self.visited_lock:
            self.visited.add(host)

        # Process CDP rows and decide enqueues
        for entry in cdp_list:
            text = entry.get("DESTINATION_HOST", "")
            head = text.split(".", 1)[0].upper() if text else ""
            entry["DESTINATION_HOST"] = head
            entry["LOCAL_HOST"] = hostname
            entry["LOCAL_IP"] = host
            entry["LOCAL_SERIAL"] = serial_numbers
            entry["LOCAL_UPTIME"] = uptime

            with self.data_lock:
                self.cdp_neighbour_details.append(entry)

            caps = entry.get("CAPABILITIES", "")
            mgmt_ip = entry.get("MANAGEMENT_IP", "")

            if "Switch" in caps and "Host" not in caps and mgmt_ip:
                should_enqueue = False
                # Ensure only one thread enqueues the same IP
                with self.visited_lock:
                    if mgmt_ip not in self.visited:
                        # mark visited to prevent duplicate enqueues
                        self.visited.add(mgmt_ip)
                        should_enqueue = True
                # Also deduplicate by hostname
                with self.data_lock:
                    if head in self.visited_hostnames:
                        should_enqueue = False
                    else:
                        if head:
                            self.visited_hostnames.add(head)
                if should_enqueue:
                    logger.debug("Enqueuing neighbor %s (%s) discovered from %s", head, mgmt_ip, host)
                    self.host_queue.put(mgmt_ip)

    def _paramiko_jump_client(self, jump_host: str, username: str, password: str) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=jump_host,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            banner_timeout=self.config.timeout,
            auth_timeout=self.config.timeout,
            timeout=self.config.timeout,
        )
        return client

    def _netmiko_via_jump(self, jump_host: str, target_ip: str, primary: bool,
                          primary_user: str, primary_pass: str, answer_user: str, answer_pass: str):
        if primary:
            j_user, j_pass = primary_user, primary_pass
            d_user, d_pass = primary_user, primary_pass
        else:
            j_user, j_pass = primary_user, primary_pass
            d_user, d_pass = answer_user, answer_pass

        jump = None
        try:
            jump = self._paramiko_jump_client(jump_host, j_user, j_pass)
            transport = jump.get_transport()
            dest_addr = (target_ip, 22)
            local_addr = ("127.0.0.1", 0)
            channel = transport.open_channel("direct-tcpip", dest_addr, local_addr)
            conn = ConnectHandler(
                device_type="cisco_ios",
                host=target_ip,
                username=d_user,
                password=d_pass,
                sock=channel,
                fast_cli=False,
                timeout=self.config.timeout,
                conn_timeout=self.config.timeout,
                banner_timeout=self.config.timeout,
                auth_timeout=self.config.timeout,
            )
            # Keep reference so we can close the jump client later when disconnecting
            conn._jump_client = jump
            return conn
        except Exception:
            # Ensure jump client is closed if we failed after creating it
            if jump is not None:
                try:
                    jump.close()
                except Exception:
                    logger.debug("Failed to close jump client after error.", exc_info=True)
            raise

    def run_device_commands(self, jump_host: str, host: str,
                           primary_user: str, primary_pass: str,
                           answer_user: str, answer_pass: str):
        """
        Try primary creds first, fall back to answer creds on authentication failure.
        Returns tuple (cdp_output, version_output) on success, or raises.
        """
        try:
            conn = self._netmiko_via_jump(
                jump_host=jump_host,
                target_ip=host,
                primary=True,
                primary_user=primary_user,
                primary_pass=primary_pass,
                answer_user=answer_user,
                answer_pass=answer_pass,
            )
            try:
                out_cdp = conn.send_command("show cdp neighbors detail", expect_string=r"#", read_timeout=self.config.timeout)
                out_ver = conn.send_command("show version", expect_string=r"#", read_timeout=self.config.timeout)
                return out_cdp, out_ver
            finally:
                try:
                    conn.disconnect()
                except Exception:
                    logger.debug("Error disconnecting Netmiko connection", exc_info=True)
                try:
                    if hasattr(conn, "_jump_client") and conn._jump_client:
                        conn._jump_client.close()
                except Exception:
                    logger.debug("Error closing jump client after disconnect", exc_info=True)
        except NetmikoAuthenticationException:
            logger.debug("Primary authentication failed for %s; attempting fallback user 'answer'", host)
            # Try with fallback credentials
            conn = None
            try:
                conn = self._netmiko_via_jump(
                    jump_host=jump_host,
                    target_ip=host,
                    primary=False,
                    primary_user=primary_user,
                    primary_pass=primary_pass,
                    answer_user=answer_user,
                    answer_pass=answer_pass,
                )
                try:
                    out_cdp = conn.send_command("show cdp neighbors detail", expect_string=r"#", read_timeout=self.config.timeout)
                    out_ver = conn.send_command("show version", expect_string=r"#", read_timeout=self.config.timeout)
                    return out_cdp, out_ver
                finally:
                    try:
                        conn.disconnect()
                    except Exception:
                        logger.debug("Error disconnecting Netmiko connection (fallback)", exc_info=True)
                    try:
                        if hasattr(conn, "_jump_client") and conn._jump_client:
                            conn._jump_client.close()
                    except Exception:
                        logger.debug("Error closing jump client after disconnect (fallback)", exc_info=True)
            except NetmikoAuthenticationException:
                logger.info("Authentication failed for both primary and fallback on %s", host)
                with self.data_lock:
                    self.authentication_errors.add(host)
                raise

    def discover_worker(self, jump_host, primary_user, primary_pass, answer_user, answer_pass):
        while True:
            try:
                host = self.host_queue.get_nowait()
            except queue.Empty:
                return
            # If another thread already marked as visited while queued, skip
            with self.visited_lock:
                if host in self.visited:
                    self.host_queue.task_done()
                    continue
            last_err = None
            for attempt in range(1, 4):
                try:
                    logger.info("[%s] Attempt %d: collecting CDP + version", host, attempt)
                    cdp_out, ver_out = self.run_device_commands(
                        jump_host, host, primary_user, primary_pass, answer_user, answer_pass
                    )
                    self.parse_outputs_and_enqueue_neighbors(host, cdp_out, ver_out)
                    last_err = None
                    break
                except NetmikoAuthenticationException:
                    logger.info("[%s] Authentication failed", host)
                    last_err = "AuthenticationError"
                    break
                except (NetmikoTimeoutException, SSHException, socket.timeout) as e:
                    logger.warning("[%s] Connection issue: %s", host, e)
                    last_err = type(e).__name__
                except Exception as e:
                    logger.exception("[%s] Unexpected error", host)
                    last_err = type(e).__name__
            # After all attempts, mark IP as visited to prevent further retries
            with self.visited_lock:
                self.visited.add(host)
            if last_err:
                with self.data_lock:
                    self.connection_errors.setdefault(host, last_err)
            self.host_queue.task_done()

    def resolve_dns_for_host(self, hname: str):
        try:
            logger.debug("[DNS] Resolving %s", hname)
            ip = socket.gethostbyname(hname)
            return hname, ip
        except socket.gaierror:
            return hname, "DNS Resolution Failed"
        except Exception as e:
            logger.exception("Unexpected DNS error for %s", hname)
            return hname, f"Error: {e}"

    def resolve_dns_parallel(self):
        names = list(self.hostnames)
        results = []
        if not names:
            return
        with ThreadPoolExecutor(max_workers=min(32, max(4, self.config.limit))) as ex:
            futs = [ex.submit(self.resolve_dns_for_host, n) for n in names]
            for f in as_completed(futs):
                try:
                    results.append(f.result())
                except Exception:
                    logger.exception("DNS worker failed while resolving names")
        with self.data_lock:
            for h, ip in results:
                self.dns_ip[h] = ip


def main():
    config = ConfigLoader()
    creds = CredentialManager()
    discoverer = NetworkDiscoverer(config)
    reporter = ExcelReporter(config.excel_template)

    # Interactive input
    site_name, seeds, primary_user, primary_pass, answer_user, answer_pass = creds.prompt_for_inputs()

    # Validate seeds: accept IPs or resolvable hostnames
    validated_seeds = []
    for s in seeds:
        try:
            # If it's a valid IP, this will succeed
            ipaddress.ip_address(s)
            validated_seeds.append(s)
        except ValueError:
            # try DNS resolution
            try:
                resolved = socket.gethostbyname(s)
                validated_seeds.append(resolved)
            except Exception:
                logger.error("Seed '%s' is not a valid IP and could not be resolved. Aborting.", s)
                raise SystemExit(1)

    # Queue seeds (mark visited to avoid duplicates)
    for s in validated_seeds:
        with discoverer.visited_lock:
            if s not in discoverer.visited:
                discoverer.visited.add(s)
                discoverer.host_queue.put(s)

    # Discovery (threaded)
    with ThreadPoolExecutor(max_workers=config.limit) as executor:
        futures = [
            executor.submit(
                discoverer.discover_worker,
                config.jump_server,
                primary_user,
                primary_pass,
                answer_user,
                answer_pass,
            )
            for _ in range(config.limit)
        ]
        for _ in as_completed(futures):
            pass
        discoverer.host_queue.join()

    # DNS resolution
    discoverer.resolve_dns_parallel()

    # Excel output
    reporter.save_to_excel(
        discoverer.cdp_neighbour_details,
        validated_seeds,
        site_name,
        discoverer.dns_ip,
        discoverer.authentication_errors,
        discoverer.connection_errors,
    )

    # Summary
    logger.info("Done!")
    logger.info(" Discovered devices: %d", len(discoverer.visited))
    logger.info(" CDP entries: %d", len(discoverer.cdp_neighbour_details))
    logger.info(" Auth errors: %d", len(discoverer.authentication_errors))
    logger.info(" Conn errors: %d", len(discoverer.connection_errors))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Exiting gracefully…")
