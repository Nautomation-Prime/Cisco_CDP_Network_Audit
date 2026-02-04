"""
CDP Network Audit Configuration Loader
=======================================

This module provides a centralized configuration loader for the CDP Network Audit tool.
It loads structured parameters from a YAML configuration file and allows environment
variables to override specific settings.

The Config class provides a clean API for accessing configuration values throughout
the application, with automatic type conversion and sensible defaults.

Usage Example:
--------------
    from ProgramFiles.config_files.config_loader import Config
    
    config = Config()
    
    # Access configuration values
    jump_host = config.jump_host
    timeout = config.default_timeout
    templates = config.cdp_template
    
    print(f"Using jump host: {jump_host}")
    print(f"Timeout: {timeout} seconds")

Design Philosophy:
------------------
- Configuration is loaded from YAML for human readability and ease of editing
- Sensitive values (credentials) can be overridden via environment variables
- The Config class provides a stable API, insulating the application from
  changes to the underlying YAML structure
- All file paths are returned as pathlib.Path objects for cross-platform compatibility
- Default values are provided for all settings to prevent runtime errors

Security Considerations:
------------------------
- Never commit sensitive credentials to the YAML file
- Use environment variables or secure credential stores (Windows Credential Manager)
  for passwords and secrets
- The YAML file should be readable only by authorized users in production
"""

import os
import yaml
from pathlib import Path
from typing import Optional, Dict, List


class Config:
    """
    Canonical configuration loader for CDP Network Audit tool.
    
    - Loads structured parameters from config.yaml
    - Allows environment variable overrides for deployment flexibility
    - Provides type-safe property accessors for all configuration values
    - Returns pathlib.Path objects for file paths (cross-platform compatibility)
    
    Attributes:
        config_file (Path): Path to the YAML configuration file
    """

    def __init__(self, config_file: str = "config.yaml"):
        """
        Initialize the configuration loader.
        
        Args:
            config_file: Path to the YAML configuration file (relative or absolute).
                        Defaults to "config.yaml" in the current directory.
        
        Raises:
            FileNotFoundError: If the specified config file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        # Determine the absolute path to the config file
        # If config_file is relative, resolve it relative to this module's directory
        if not Path(config_file).is_absolute():
            # Config file is in the same directory as this module
            module_dir = Path(__file__).parent
            self._config_file = module_dir / config_file
        else:
            self._config_file = Path(config_file)
        
        # Load the YAML configuration
        self._config = self._load_yaml()
        
        # Cache for environment variable lookups (populated on-demand)
        self._env_cache: Dict[str, Optional[str]] = {}

    def _load_yaml(self) -> dict:
        """
        Load and parse the YAML configuration file.
        
        Returns:
            Dictionary containing the parsed YAML configuration.
        
        Raises:
            FileNotFoundError: If the config file doesn't exist.
            yaml.YAMLError: If the YAML file is malformed.
        """
        if not self._config_file.exists():
            raise FileNotFoundError(
                f"Configuration file not found: {self._config_file}\n"
                f"Please ensure config.yaml exists in the ProgramFiles/config_files/ directory."
            )
        
        with open(self._config_file, "r", encoding="utf-8") as f:
            try:
                config_data = yaml.safe_load(f)
                if config_data is None:
                    # Empty YAML file
                    return {}
                return config_data
            except yaml.YAMLError as e:
                raise yaml.YAMLError(
                    f"Error parsing YAML configuration file {self._config_file}: {e}"
                )

    def _get_env(self, var_name: str) -> Optional[str]:
        """
        Get an environment variable value with caching.
        
        Args:
            var_name: Name of the environment variable.
        
        Returns:
            The environment variable value, or None if not set.
        """
        if var_name not in self._env_cache:
            value = os.getenv(var_name)
            # Strip whitespace and treat empty strings as None
            self._env_cache[var_name] = value.strip() if value else None
        return self._env_cache[var_name]

    # =========================================================================
    # NETWORK CONNECTION SETTINGS
    # =========================================================================

    @property
    def JUMP_HOST(self) -> str:
        """
        Jump/bastion server hostname or IP address.
        Can be overridden via CDP_JUMP_SERVER environment variable.
        
        Returns:
            Jump host address (string), or empty string if not configured.
        """
        env_value = self._get_env("CDP_JUMP_SERVER")
        if env_value is not None:
            return env_value
        return self._config.get("network", {}).get("jump_host", "")

    @property
    def DEVICE_TYPE(self) -> str:
        """
        Netmiko device type for SSH connections.
        
        Returns:
            Device type string (e.g., "cisco_ios").
        """
        return self._config.get("network", {}).get("device_type", "cisco_ios")

    @property
    def SSH_PORT(self) -> int:
        """
        SSH port for device connections.
        
        Returns:
            SSH port number (default: 22).
        """
        return int(self._config.get("network", {}).get("ssh_port", 22))

    @property
    def DEFAULT_LIMIT(self) -> int:
        """
        Maximum number of concurrent worker threads for device discovery.
        Can be overridden via CDP_LIMIT environment variable.
        
        Returns:
            Worker limit (default: 10).
        """
        env_value = self._get_env("CDP_LIMIT")
        if env_value is not None:
            try:
                return int(env_value)
            except ValueError:
                # Fall back to config file value if env var is invalid
                pass
        return int(self._config.get("network", {}).get("default_limit", 10))

    @property
    def DEFAULT_TIMEOUT(self) -> int:
        """
        Timeout in seconds for SSH operations.
        Can be overridden via CDP_TIMEOUT environment variable.
        
        Returns:
            Timeout in seconds (default: 10).
        """
        env_value = self._get_env("CDP_TIMEOUT")
        if env_value is not None:
            try:
                return int(env_value)
            except ValueError:
                pass
        return int(self._config.get("network", {}).get("default_timeout", 10))

    @property
    def MAX_RETRY_ATTEMPTS(self) -> int:
        """
        Maximum number of connection retry attempts per device.
        
        Returns:
            Retry count (default: 3).
        """
        return int(self._config.get("network", {}).get("max_retry_attempts", 3))

    @property
    def DNS_MAX_WORKERS(self) -> int:
        """
        Maximum number of DNS resolution worker threads.
        
        Returns:
            Max DNS workers (default: 32).
        """
        return int(self._config.get("network", {}).get("dns_max_workers", 32))

    @property
    def DNS_MIN_WORKERS(self) -> int:
        """
        Minimum number of DNS resolution worker threads.
        
        Returns:
            Min DNS workers (default: 4).
        """
        return int(self._config.get("network", {}).get("dns_min_workers", 4))

    # =========================================================================
    # CREDENTIAL SETTINGS
    # =========================================================================

    @property
    def CRED_TARGET(self) -> str:
        """
        Windows Credential Manager target for primary credentials.
        Can be overridden via CDP_PRIMARY_CRED_TARGET environment variable.
        
        Returns:
            Credential target name (default: "MyApp/ADM").
        """
        env_value = self._get_env("CDP_PRIMARY_CRED_TARGET")
        if env_value is not None:
            return env_value
        return self._config.get("credentials", {}).get("cred_target", "MyApp/ADM")

    @property
    def ALT_CREDS(self) -> str:
        """
        Windows Credential Manager target for answer/fallback credentials.
        Can be overridden via CDP_ANSWER_CRED_TARGET environment variable.
        
        Returns:
            Credential target name (default: "MyApp/Answer").
        """
        env_value = self._get_env("CDP_ANSWER_CRED_TARGET")
        if env_value is not None:
            return env_value
        return self._config.get("credentials", {}).get("alt_creds", "MyApp/Answer")

    # =========================================================================
    # FILE PATHS
    # =========================================================================

    @property
    def BASE_DIR(self) -> Path:
        """
        Base directory for the application.
        
        Returns:
            Path object for the base directory (default: current directory).
        """
        base_dir_str = self._config.get("file_paths", {}).get("base_dir", ".")
        return Path(base_dir_str)

    @property
    def CDP_TEMPLATE(self) -> Path:
        """
        Path to the TextFSM template for parsing 'show cdp neighbors detail'.
        
        Returns:
            Path object for the CDP TextFSM template.
        """
        template_path = self._config.get("file_paths", {}).get(
            "cdp_template",
            "ProgramFiles/textfsm/cisco_ios_show_cdp_neighbors_detail.textfsm"
        )
        return self.BASE_DIR / template_path

    @property
    def VER_TEMPLATE(self) -> Path:
        """
        Path to the TextFSM template for parsing 'show version'.
        
        Returns:
            Path object for the version TextFSM template.
        """
        template_path = self._config.get("file_paths", {}).get(
            "ver_template",
            "ProgramFiles/textfsm/cisco_ios_show_version.textfsm"
        )
        return self.BASE_DIR / template_path

    @property
    def EXCEL_TEMPLATE(self) -> Path:
        """
        Path to the Excel template file for audit reports.
        
        Returns:
            Path object for the Excel template.
        """
        template_path = self._config.get("file_paths", {}).get(
            "excel_template",
            "ProgramFiles/config_files/1 - CDP Network Audit _ Template.xlsx"
        )
        return self.BASE_DIR / template_path

    @property
    def LOGGING_CONFIG_PATH(self) -> Path:
        """
        Path to the logging configuration file.
        Can be overridden via LOGGING_CONFIG environment variable.
        
        Returns:
            Path object for the logging config file.
        """
        env_value = self._get_env("LOGGING_CONFIG")
        if env_value is not None:
            return Path(env_value)
        
        config_path = self._config.get("file_paths", {}).get(
            "logging_config_path",
            "ProgramFiles/config_files/logging.conf"
        )
        return self.BASE_DIR / config_path

    # =========================================================================
    # EXCEL REPORT SETTINGS
    # =========================================================================

    @property
    def EXCEL_SHEET_AUDIT(self) -> str:
        """Excel sheet name for audit data."""
        return self._config.get("excel", {}).get("sheets", {}).get("audit", "Audit")

    @property
    def EXCEL_SHEET_DNS(self) -> str:
        """Excel sheet name for DNS resolution data."""
        return self._config.get("excel", {}).get("sheets", {}).get("dns", "DNS Resolved")

    @property
    def EXCEL_SHEET_AUTH_ERRORS(self) -> str:
        """Excel sheet name for authentication errors."""
        return self._config.get("excel", {}).get("sheets", {}).get("auth_errors", "Authentication Errors")

    @property
    def EXCEL_SHEET_CONN_ERRORS(self) -> str:
        """Excel sheet name for connection errors."""
        return self._config.get("excel", {}).get("sheets", {}).get("conn_errors", "Connection Errors")

    @property
    def EXCEL_CELL_SITE_NAME(self) -> str:
        """Excel cell address for site name metadata."""
        return self._config.get("excel", {}).get("metadata_cells", {}).get("site_name", "B4")

    @property
    def EXCEL_CELL_DATE(self) -> str:
        """Excel cell address for date metadata."""
        return self._config.get("excel", {}).get("metadata_cells", {}).get("date", "B5")

    @property
    def EXCEL_CELL_TIME(self) -> str:
        """Excel cell address for time metadata."""
        return self._config.get("excel", {}).get("metadata_cells", {}).get("time", "B6")

    @property
    def EXCEL_CELL_PRIMARY_SEED(self) -> str:
        """Excel cell address for primary seed device metadata."""
        return self._config.get("excel", {}).get("metadata_cells", {}).get("primary_seed", "B7")

    @property
    def EXCEL_CELL_SECONDARY_SEED(self) -> str:
        """Excel cell address for secondary seed device metadata."""
        return self._config.get("excel", {}).get("metadata_cells", {}).get("secondary_seed", "B8")

    @property
    def EXCEL_AUDIT_DATA_START_ROW(self) -> int:
        """Starting row for audit data in Excel (0-indexed)."""
        return int(self._config.get("excel", {}).get("data_start_rows", {}).get("audit", 11))

    @property
    def EXCEL_OTHER_DATA_START_ROW(self) -> int:
        """Starting row for other data sheets in Excel (0-indexed)."""
        return int(self._config.get("excel", {}).get("data_start_rows", {}).get("other", 4))

    @property
    def EXCEL_SECONDARY_SEED_DEFAULT(self) -> str:
        """Default text when no secondary seed device is provided."""
        return self._config.get("excel", {}).get("defaults", {}).get(
            "secondary_seed_default",
            "Secondary Seed device not given"
        )

    @property
    def EXCEL_AUDIT_COLUMNS(self) -> List[str]:
        """Column names for audit data."""
        return self._config.get("excel", {}).get("columns_audit", [
            "LOCAL_HOST", "LOCAL_IP", "LOCAL_PORT", "LOCAL_SERIAL", "LOCAL_UPTIME",
            "DESTINATION_HOST", "REMOTE_PORT", "MANAGEMENT_IP", "PLATFORM"
        ])

    @property
    def EXCEL_DNS_COLUMNS(self) -> List[str]:
        """Column names for DNS resolution data."""
        return self._config.get("excel", {}).get("columns_dns", ["Hostname", "IP Address"])

    @property
    def EXCEL_AUTH_ERROR_COLUMNS(self) -> List[str]:
        """Column names for authentication errors."""
        return self._config.get("excel", {}).get("columns_auth_errors", ["Authentication Errors"])

    @property
    def EXCEL_CONN_ERROR_COLUMNS(self) -> List[str]:
        """Column names for connection errors."""
        return self._config.get("excel", {}).get("columns_conn_errors", ["IP Address", "Error"])

    # =========================================================================
    # DNS RESOLUTION SETTINGS
    # =========================================================================

    @property
    def DNS_UNRESOLVED_MARKER(self) -> str:
        """Marker text for unresolved DNS lookups in Excel output."""
        return self._config.get("dns", {}).get("unresolved_marker", "UNRESOLVED")

    @property
    def DNS_ERROR_MARKER(self) -> str:
        """Marker text for DNS resolution errors in Excel output."""
        return self._config.get("dns", {}).get("error_marker", "ERROR")

    # =========================================================================
    # UTILITY METHODS
    # =========================================================================

    def __repr__(self) -> str:
        """
        String representation of the Config object.
        
        Returns:
            String describing the config file and loaded sections.
        """
        sections = list(self._config.keys())
        return f"<Config file={self._config_file} sections={sections}>"

    def validate_required_files(self) -> bool:
        """
        Validate that all required files (templates, Excel template) exist.
        
        Returns:
            True if all required files exist, False otherwise.
        """
        required_files = [
            ("CDP Template", self.CDP_TEMPLATE),
            ("Version Template", self.VER_TEMPLATE),
            ("Excel Template", self.EXCEL_TEMPLATE),
        ]
        
        all_exist = True
        for name, path in required_files:
            if not path.exists():
                print(f"ERROR: Required file not found: {name} at {path}")
                all_exist = False
        
        return all_exist

    def get_all_settings(self) -> Dict:
        """
        Get a dictionary of all configuration settings (for debugging/logging).
        
        Returns:
            Dictionary containing all current configuration values.
        """
        return {
            "network": {
                "jump_host": self.JUMP_HOST,
                "device_type": self.DEVICE_TYPE,
                "ssh_port": self.SSH_PORT,
                "default_limit": self.DEFAULT_LIMIT,
                "default_timeout": self.DEFAULT_TIMEOUT,
                "max_retry_attempts": self.MAX_RETRY_ATTEMPTS,
                "dns_max_workers": self.DNS_MAX_WORKERS,
                "dns_min_workers": self.DNS_MIN_WORKERS,
            },
            "credentials": {
                "cred_target": self.CRED_TARGET,
                "alt_creds": self.ALT_CREDS,
            },
            "file_paths": {
                "base_dir": str(self.BASE_DIR),
                "cdp_template": str(self.CDP_TEMPLATE),
                "ver_template": str(self.VER_TEMPLATE),
                "excel_template": str(self.EXCEL_TEMPLATE),
                "logging_config_path": str(self.LOGGING_CONFIG_PATH),
            },
            "excel": {
                "sheets": {
                    "audit": self.EXCEL_SHEET_AUDIT,
                    "dns": self.EXCEL_SHEET_DNS,
                    "auth_errors": self.EXCEL_SHEET_AUTH_ERRORS,
                    "conn_errors": self.EXCEL_SHEET_CONN_ERRORS,
                },
            },
            "dns": {
                "unresolved_marker": self.DNS_UNRESOLVED_MARKER,
                "error_marker": self.DNS_ERROR_MARKER,
            },
        }


# =============================================================================
# Module-level instance for backward compatibility
# =============================================================================
# This allows existing code to import config values directly:
#   from ProgramFiles.config_files.config_loader import JUMP_HOST, DEFAULT_LIMIT
# 
# However, the preferred approach is to import the Config class and instantiate it:
#   from ProgramFiles.config_files.config_loader import Config
#   config = Config()
#   jump_host = config.JUMP_HOST

# Create a default config instance
_default_config = Config()

# Export individual settings for backward compatibility
JUMP_HOST = _default_config.JUMP_HOST
DEVICE_TYPE = _default_config.DEVICE_TYPE
SSH_PORT = _default_config.SSH_PORT
DEFAULT_LIMIT = _default_config.DEFAULT_LIMIT
DEFAULT_TIMEOUT = _default_config.DEFAULT_TIMEOUT
MAX_RETRY_ATTEMPTS = _default_config.MAX_RETRY_ATTEMPTS
DNS_MAX_WORKERS = _default_config.DNS_MAX_WORKERS
DNS_MIN_WORKERS = _default_config.DNS_MIN_WORKERS
CRED_TARGET = _default_config.CRED_TARGET
ALT_CREDS = _default_config.ALT_CREDS
BASE_DIR = _default_config.BASE_DIR
CDP_TEMPLATE = _default_config.CDP_TEMPLATE
VER_TEMPLATE = _default_config.VER_TEMPLATE
EXCEL_TEMPLATE = _default_config.EXCEL_TEMPLATE
LOGGING_CONFIG_PATH = _default_config.LOGGING_CONFIG_PATH
EXCEL_SHEET_AUDIT = _default_config.EXCEL_SHEET_AUDIT
EXCEL_SHEET_DNS = _default_config.EXCEL_SHEET_DNS
EXCEL_SHEET_AUTH_ERRORS = _default_config.EXCEL_SHEET_AUTH_ERRORS
EXCEL_SHEET_CONN_ERRORS = _default_config.EXCEL_SHEET_CONN_ERRORS
EXCEL_CELL_SITE_NAME = _default_config.EXCEL_CELL_SITE_NAME
EXCEL_CELL_DATE = _default_config.EXCEL_CELL_DATE
EXCEL_CELL_TIME = _default_config.EXCEL_CELL_TIME
EXCEL_CELL_PRIMARY_SEED = _default_config.EXCEL_CELL_PRIMARY_SEED
EXCEL_CELL_SECONDARY_SEED = _default_config.EXCEL_CELL_SECONDARY_SEED
EXCEL_AUDIT_DATA_START_ROW = _default_config.EXCEL_AUDIT_DATA_START_ROW
EXCEL_OTHER_DATA_START_ROW = _default_config.EXCEL_OTHER_DATA_START_ROW
EXCEL_SECONDARY_SEED_DEFAULT = _default_config.EXCEL_SECONDARY_SEED_DEFAULT
EXCEL_AUDIT_COLUMNS = _default_config.EXCEL_AUDIT_COLUMNS
EXCEL_DNS_COLUMNS = _default_config.EXCEL_DNS_COLUMNS
EXCEL_AUTH_ERROR_COLUMNS = _default_config.EXCEL_AUTH_ERROR_COLUMNS
EXCEL_CONN_ERROR_COLUMNS = _default_config.EXCEL_CONN_ERROR_COLUMNS
DNS_UNRESOLVED_MARKER = _default_config.DNS_UNRESOLVED_MARKER
DNS_ERROR_MARKER = _default_config.DNS_ERROR_MARKER
