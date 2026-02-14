"""Excel report writer."""

import datetime
import logging
import shutil
from pathlib import Path
from typing import Dict, List

import openpyxl
import pandas as pd

from .app_config import config

logger = logging.getLogger(__name__)


class ExcelReporter:
    """Handles writing discovery results to an Excel workbook based on a template."""

    def __init__(self, excel_template: Path) -> None:
        self.excel_template = excel_template

    def save_to_excel(
        self,
        details_list: List[Dict],
        hosts: List[str],
        site_name: str,
        dns_ip: Dict[str, str],
        auth_errors: set,
        conn_errors: Dict[str, str],
    ) -> None:
        """Persist collected data to an Excel file cloned from the template.

        Args:
            details_list: Parsed CDP neighbor rows to place on the Audit sheet.
            hosts: Seed devices (used to stamp primary/secondary seed cells).
            site_name: Site label used in the output filename and metadata cells.
            dns_ip: Hostname to IP mappings for the DNS sheet.
            auth_errors: IPs that failed authentication (Auth Errors sheet).
            conn_errors: IPs that failed to connect with error labels.
        """
        df = pd.DataFrame(details_list, columns=config.EXCEL_AUDIT_COLUMNS)
        dns_array = pd.DataFrame(dns_ip.items(), columns=config.EXCEL_DNS_COLUMNS)
        auth_array = pd.DataFrame(sorted(list(auth_errors)), columns=config.EXCEL_AUTH_ERROR_COLUMNS)
        conn_array = pd.DataFrame(conn_errors.items(), columns=config.EXCEL_CONN_ERROR_COLUMNS)

        filepath = f"{site_name}_CDP_Network_Audit.xlsx"
        shutil.copy2(src=self.excel_template, dst=filepath)

        date_now = datetime.datetime.now().strftime("%d %B %Y")
        time_now = datetime.datetime.now().strftime("%H:%M")
        wb = openpyxl.load_workbook(filepath)
        ws1 = wb[config.EXCEL_SHEET_AUDIT]
        ws1[config.EXCEL_CELL_SITE_NAME] = site_name
        ws1[config.EXCEL_CELL_DATE] = date_now
        ws1[config.EXCEL_CELL_TIME] = time_now
        ws1[config.EXCEL_CELL_PRIMARY_SEED] = hosts[0] if hosts else ""
        ws1[config.EXCEL_CELL_SECONDARY_SEED] = (
            hosts[1] if len(hosts) > 1 else config.EXCEL_SECONDARY_SEED_DEFAULT
        )
        wb.save(filepath)
        wb.close()

        with pd.ExcelWriter(filepath, engine="openpyxl", if_sheet_exists="overlay", mode="a") as writer:
            df.to_excel(
                writer,
                index=False,
                sheet_name=config.EXCEL_SHEET_AUDIT,
                header=False,
                startrow=config.EXCEL_AUDIT_DATA_START_ROW,
            )
            dns_array.to_excel(
                writer,
                index=False,
                sheet_name=config.EXCEL_SHEET_DNS,
                header=False,
                startrow=config.EXCEL_OTHER_DATA_START_ROW,
            )
            auth_array.to_excel(
                writer,
                index=False,
                sheet_name=config.EXCEL_SHEET_AUTH_ERRORS,
                header=False,
                startrow=config.EXCEL_OTHER_DATA_START_ROW,
            )
            conn_array.to_excel(
                writer,
                index=False,
                sheet_name=config.EXCEL_SHEET_CONN_ERRORS,
                header=False,
                startrow=config.EXCEL_OTHER_DATA_START_ROW,
            )
