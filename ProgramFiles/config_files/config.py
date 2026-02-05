"""
CDP Network Audit Configuration (DEPRECATED - Backward Compatibility Wrapper)
==============================================================================

THIS FILE IS DEPRECATED!
------------------------
This file is maintained for backward compatibility only. The configuration
system has been migrated to YAML for easier end-user customization.

NEW CONFIGURATION SYSTEM:
- Configuration is now loaded from config.yaml
- Settings can be customized by editing config.yaml
- See config.yaml for detailed documentation of all settings
- The config_loader.py module handles loading and parsing

MIGRATION GUIDE:
- All configuration values are now in config.yaml
- This file simply re-exports values from config_loader for compatibility
- Update your imports to use config_loader directly if possible
- See config_loader.py for the new API

For new projects, please use:
    from ProgramFiles.config_files.config_loader import Config
    config = Config()

Author: Christopher Davies T/A Nautomation Prime
Email: nautomationprime.f3wfe@simplelogin.com

Copyright (c) 2026 Christopher Davies T/A Nautomation Prime
Licensed under the GNU General Public License v3.0 (GPL-3.0)
See the LICENSE file in the project root for full license text.
"""

# Re-export all configuration values from the new YAML-based config loader
# This maintains backward compatibility with existing code that imports from config.py
from ProgramFiles.config_files.config_loader import (
    JUMP_HOST,
    DEVICE_TYPE,
    SSH_PORT,
    DEFAULT_LIMIT,
    DEFAULT_TIMEOUT,
    MAX_RETRY_ATTEMPTS,
    DNS_MAX_WORKERS,
    DNS_MIN_WORKERS,
    CRED_TARGET,
    ALT_CREDS,
    BASE_DIR,
    CDP_TEMPLATE,
    VER_TEMPLATE,
    EXCEL_TEMPLATE,
    LOGGING_CONFIG_PATH,
    EXCEL_SHEET_AUDIT,
    EXCEL_SHEET_DNS,
    EXCEL_SHEET_AUTH_ERRORS,
    EXCEL_SHEET_CONN_ERRORS,
    EXCEL_CELL_SITE_NAME,
    EXCEL_CELL_DATE,
    EXCEL_CELL_TIME,
    EXCEL_CELL_PRIMARY_SEED,
    EXCEL_CELL_SECONDARY_SEED,
    EXCEL_AUDIT_DATA_START_ROW,
    EXCEL_OTHER_DATA_START_ROW,
    EXCEL_SECONDARY_SEED_DEFAULT,
    EXCEL_AUDIT_COLUMNS,
    EXCEL_DNS_COLUMNS,
    EXCEL_AUTH_ERROR_COLUMNS,
    EXCEL_CONN_ERROR_COLUMNS,
    DNS_UNRESOLVED_MARKER,
    DNS_ERROR_MARKER,
)

# Make all imports available when using "from config import *"
__all__ = [
    'JUMP_HOST',
    'DEVICE_TYPE',
    'SSH_PORT',
    'DEFAULT_LIMIT',
    'DEFAULT_TIMEOUT',
    'MAX_RETRY_ATTEMPTS',
    'DNS_MAX_WORKERS',
    'DNS_MIN_WORKERS',
    'CRED_TARGET',
    'ALT_CREDS',
    'BASE_DIR',
    'CDP_TEMPLATE',
    'VER_TEMPLATE',
    'EXCEL_TEMPLATE',
    'LOGGING_CONFIG_PATH',
    'EXCEL_SHEET_AUDIT',
    'EXCEL_SHEET_DNS',
    'EXCEL_SHEET_AUTH_ERRORS',
    'EXCEL_SHEET_CONN_ERRORS',
    'EXCEL_CELL_SITE_NAME',
    'EXCEL_CELL_DATE',
    'EXCEL_CELL_TIME',
    'EXCEL_CELL_PRIMARY_SEED',
    'EXCEL_CELL_SECONDARY_SEED',
    'EXCEL_AUDIT_DATA_START_ROW',
    'EXCEL_OTHER_DATA_START_ROW',
    'EXCEL_SECONDARY_SEED_DEFAULT',
    'EXCEL_AUDIT_COLUMNS',
    'EXCEL_DNS_COLUMNS',
    'EXCEL_AUTH_ERROR_COLUMNS',
    'EXCEL_CONN_ERROR_COLUMNS',
    'DNS_UNRESOLVED_MARKER',
    'DNS_ERROR_MARKER',
]
