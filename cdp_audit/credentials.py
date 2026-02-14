"""Credential collection and storage helpers."""

import logging
import os
import sys
from typing import List, Optional, Tuple

from .app_config import config

logger = logging.getLogger(__name__)


class CredentialManager:
    """
    Helper class to collect credentials from:
    - Windows Credential Manager (when on Windows and entries exist)
    - Interactive prompts (fallback)
    - Optional persistence back to Windows Credential Manager
    """

    def __init__(self) -> None:
        self.primary_target = os.getenv("CDP_PRIMARY_CRED_TARGET", config.CRED_TARGET)
        self.answer_target = os.getenv("CDP_ANSWER_CRED_TARGET", config.ALT_CREDS)

    def _read_win_cred(self, target_name: str) -> Tuple[Optional[str], Optional[str]]:
        """Attempt to read a generic credential from Windows Credential Manager."""
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
        """Write or update a generic credential in Windows Credential Manager."""
        try:
            if not sys.platform.startswith("win"):
                logger.warning("Not a Windows platform; cannot store credentials in Credential Manager.")
                return False
            import win32cred  # type: ignore

            blob_bytes = password.encode("utf-16le")
            credential = {
                "Type": win32cred.CRED_TYPE_GENERIC,
                "TargetName": target,
                "UserName": username,
                "CredentialBlob": blob_bytes,
                "Comment": "Created by CDP Network Audit tool",
                "Persist": persist,
            }
            try:
                win32cred.CredWrite(credential, 0)
            except TypeError as exc:
                logger.debug(
                    "CredWrite rejected bytes for CredentialBlob (%s). Retrying with unicode string.",
                    exc,
                )
                credential["CredentialBlob"] = password
                win32cred.CredWrite(credential, 0)
            logger.info("Stored/updated credentials in Windows Credential Manager: %s", target)
            return True
        except Exception:
            logger.exception("Failed to write credentials for '%s'", target)
            return False

    def _prompt_yes_no(self, msg: str, default_no: bool = True) -> bool:
        """Simple interactive [y/N] or [Y/n] prompt."""
        suffix = " [y/N] " if default_no else " [Y/n] "
        ans = input(msg + suffix).strip().lower()
        if ans == "":
            return not default_no
        return ans in ("y", "yes")

    def get_secret_with_fallback(
        self,
        display_name: str,
        cred_target: Optional[str] = None,
        prompt_user: Optional[str] = None,
        prompt_pass: Optional[str] = None,
        fixed_username: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Obtain credentials from CredMan or interactive prompt."""
        if cred_target and sys.platform.startswith("win"):
            user, pwd = self._read_win_cred(cred_target)
            if user and pwd:
                if fixed_username and fixed_username.lower() != user.lower():
                    logger.info(
                        "Loaded %s password from CredMan (%s). Using fixed username '%s'.",
                        display_name,
                        cred_target,
                        fixed_username,
                    )
                    return fixed_username, pwd
                logger.info(
                    "Loaded %s credentials from Windows Credential Manager (%s).",
                    display_name,
                    cred_target,
                )
                return (fixed_username or user), pwd

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

    def prompt_for_inputs(self) -> Tuple[str, List[str], str, str, str, str]:
        """Interactively collect site name, seeds, and credentials.

        Returns:
            (site_name, seeds, primary_user, primary_pass, answer_user, answer_pass)
        """
        max_site_name = 50
        max_seeds = 500

        logger.info("=== CDP Network Audit ===")

        site_name = input("Enter site name (used in Excel filename, max 50 chars): ").strip()
        while not site_name or len(site_name) > max_site_name:
            if not site_name:
                site_name = input("Site name cannot be empty. Please enter site name: ").strip()
            else:
                logger.warning("Site name too long (%d > %d chars)", len(site_name), max_site_name)
                site_name = input(f"Site name too long. Max {max_site_name} chars: ").strip()

        seed_str = input("Enter one or more seed device IPs or hostnames (comma-separated, max 500): ").strip()
        while not seed_str:
            seed_str = input("Seed IPs cannot be empty. Please enter one or more IPs: ").strip()

        seeds = [s.strip() for s in seed_str.split(",") if s.strip()]

        if len(seeds) > max_seeds:
            logger.error("Too many seeds provided (%d > %d max). Aborting.", len(seeds), max_seeds)
            raise SystemExit(1)

        stored_user, stored_pass = (
            self._read_win_cred(self.primary_target) if sys.platform.startswith("win") else (None, None)
        )
        if stored_user and stored_pass:
            logger.info("Found stored Primary user: %s (target: %s)", stored_user, self.primary_target)
            override = input("Press Enter to accept, or type a different username: ").strip()
            if override:
                import getpass

                primary_user = override
                primary_pass = getpass.getpass("Enter switch/jump password (Primary): ")
                if self._prompt_yes_no(
                    f"Save these Primary creds to Credential Manager as '{self.primary_target}'?",
                    default_no=True,
                ):
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
            if self._prompt_yes_no(
                f"Store Primary creds in Credential Manager as '{self.primary_target}'?",
                default_no=True,
            ):
                self._write_win_cred(self.primary_target, primary_user, primary_pass)

        answer_user = "answer"
        ans_user, ans_pass = (
            self._read_win_cred(self.answer_target) if sys.platform.startswith("win") else (None, None)
        )
        if ans_user and ans_pass:
            logger.info(
                "Loaded Answer password from Credential Manager (%s). Username fixed to 'answer'.",
                self.answer_target,
            )
            answer_pass = ans_pass
        else:
            _, answer_pass = self.get_secret_with_fallback(
                display_name="Answer (device fallback)",
                cred_target=None,
                prompt_user=None,
                prompt_pass="Enter 'answer' password: ",
                fixed_username="answer",
            )
            if self._prompt_yes_no(
                f"Store 'answer' password in Credential Manager as '{self.answer_target}'?",
                default_no=True,
            ):
                self._write_win_cred(self.answer_target, answer_user, answer_pass)

        return site_name, seeds, primary_user, primary_pass, answer_user, answer_pass
