import json
import os
import sys

# Determine the base path, whether running from source or as a PyInstaller bundle
if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
    # Running as a PyInstaller bundle
    base_path = sys._MEIPASS
else:
    # Running as a normal script
    base_path = os.path.abspath(".")

CONFIG_FILE = os.path.join(base_path, "config.json")

DEFAULT_CONFIG = {
    "host": "127.0.0.1",
    "port": 8080,
    "timeout": 30
}

def load_config():
    """
    Loads the configuration from config.json.
    If the file doesn't exist, it creates it with default values.
    """
    if not os.path.exists(CONFIG_FILE):
        save_config(DEFAULT_CONFIG)
        return DEFAULT_CONFIG
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            # Ensure all default keys are present
            config.setdefault("host", DEFAULT_CONFIG["host"])
            config.setdefault("port", DEFAULT_CONFIG["port"])
            config.setdefault("timeout", DEFAULT_CONFIG["timeout"])
            return config
    except (json.JSONDecodeError, IOError):
        # If file is corrupted or unreadable, return defaults
        return DEFAULT_CONFIG

def save_config(config: dict):
    """Saves the given configuration dict to config.json."""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(config, f, indent=4)
    except IOError as e:
        print(f"Error saving config file: {e}")

