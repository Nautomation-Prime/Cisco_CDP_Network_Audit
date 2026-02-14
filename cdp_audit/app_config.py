"""Application configuration access.

Imports the YAML-backed Config object from ProgramFiles for app-wide settings.
"""

from ProgramFiles.config_files.config_loader import Config

config = Config()
