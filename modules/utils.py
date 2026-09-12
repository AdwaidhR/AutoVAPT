"""
Shared utilities - stdlib only. No third-party imports anywhere in this
module, or in any module of this project.
"""
import sys
import json
import time
import shutil
import subprocess

COLORS = {
    "INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
    "ERR": "\033[91m", "END": "\033[0m", "BOLD": "\033[1m", "DIM": "\033[2m",
}

VERBOSE = False


def set_verbose(v):
    global VERBOSE
    VERBOSE = v


def banner():
    print(f"""{COLORS['BOLD']}
   _         _        __     ___    ____ _____
  / \\  _   _| |_ ___  \\ \\   / / \\  |  _ \\_   _|
 / _ \\| | | | __/ _ \\  \\ \\ / / _ \\ | |_) || |
/ ___ \\ |_| | || (_) |  \\ V / ___ \\|  __/ | |
/_/   \\_\\__,_|\\__\\___/    \\_/_/   \\_\\_|    |_|

  Automated VAPT & Recon Framework  |  stdlib-core  |  AUTHORIZED USE ONLY
{COLORS['END']}""")


def log(tag, msg):
    key = tag.split()[0]
    color = COLORS.get(key, COLORS["INFO"])
    print(f"{color}[{tag}]{COLORS['END']} {msg}")


def vlog(msg):
    if VERBOSE:
        print(f"{COLORS['DIM']}[debug]{COLORS['END']} {msg}")


def which(binary):
    """Thin wrapper so every module checks tool availability the same way."""
    return shutil.which(binary)


def run_cmd(cmd, timeout=20):
    """
    Run an external command safely. Returns (success, stdout, stderr).
    Never raises - callers should always be able to continue if a tool
    is missing, times out, or errors out.
    """
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return proc.returncode == 0, proc.stdout, proc.stderr
    except FileNotFoundError:
        return False, "", f"{cmd[0]}: not installed"
    except subprocess.TimeoutExpired:
        return False, "", f"{cmd[0]}: timed out after {timeout}s"
    except Exception as e:
        return False, "", str(e)


def load_json(path, default=None):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return default if default is not None else {}


def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def now_iso():
    return time.strftime("%Y-%m-%dT%H:%M:%S")


def safe_get(d, *keys, default=None):
    """Nested dict access that never raises."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur
