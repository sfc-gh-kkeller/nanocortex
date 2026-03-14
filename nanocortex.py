#!/usr/bin/env python3
"""
nanocortex - Minimal Snowflake Cortex Agent coding assistant

A single-file coding agent that uses the Snowflake Cortex Agent API.
Inspired by nanocode (https://github.com/1rgs/nanocode).

Features:
- Zero external dependencies (stdlib only!)
- PAT (Programmatic Access Token) authentication  
- Client-side tools: read, write, edit, glob, grep, bash
- SSE streaming with full tool call support
- Multi-turn conversation with tool execution loop

Tool Execution:
    Most tools (bash, read, write, edit, glob, grep) execute client-side.
    web_search and snowflake_sql_execute must execute server-side via Cortex Agent API.
    If server-side execution is unavailable, nanocortex errors (no fallbacks).

Environment Variables:
    SNOWFLAKE_ACCOUNT   - Account identifier (e.g., "myorg-myaccount")
    SNOWFLAKE_USER      - Username  
    SNOWFLAKE_PAT       - Programmatic Access Token
    SNOWFLAKE_WAREHOUSE - (optional) Default warehouse for SQL execution

Usage:
    export SNOWFLAKE_ACCOUNT="myorg-myaccount"
    export SNOWFLAKE_USER="myuser"
    export SNOWFLAKE_PAT="your_pat_token"
    python nanocortex.py

Commands:
    /c  - Clear conversation
    /q  - Quit (or 'exit')

Author: Kevin Keller
License: MIT
"""

import argparse
import glob as globlib
import json
import os
import re
import readline
import subprocess
import sys
import threading
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple

HISTORY_FILE = Path("~/.nanocortex_history").expanduser()
MAX_HISTORY = 1000

# Try to import snowflake.connector for SQL execution (preferred method)
try:
    import snowflake.connector
    HAS_SF_CONNECTOR = True
except ImportError:
    HAS_SF_CONNECTOR = False

# Try to import cryptography for JWT/private key auth (optional)
try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.backends import default_backend
    import hashlib
    import base64
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

# Try to import tomllib (Python 3.11+) or tomli
try:
    import tomllib
except ImportError:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
BLUE, CYAN, GREEN, YELLOW, RED, MAGENTA = "\033[34m", "\033[36m", "\033[32m", "\033[33m", "\033[31m", "\033[35m"

# ---------------------------------------------------------------------------
# Connection Management (reads ~/.snowflake/connections.toml)
# ---------------------------------------------------------------------------

def find_config_files() -> Tuple[Optional[Path], Optional[Path]]:
    """Find Snowflake config.toml and connections.toml in standard locations."""
    snowflake_home = Path(os.environ.get("SNOWFLAKE_HOME", "~/.snowflake")).expanduser()
    locations = [
        snowflake_home,
        Path("~/.snowflake").expanduser(),
        Path("~/.config/snowflake").expanduser(),
    ]
    if sys.platform == "darwin":
        locations.append(Path("~/Library/Application Support/snowflake").expanduser())
    
    config_file, connections_file = None, None
    for loc in locations:
        if not config_file and (loc / "config.toml").exists():
            config_file = loc / "config.toml"
        if not connections_file and (loc / "connections.toml").exists():
            connections_file = loc / "connections.toml"
    return config_file, connections_file


def load_connections() -> Tuple[Dict[str, Dict], str]:
    """Load connections from config.toml and connections.toml."""
    if not tomllib:
        return {}, "default"
    
    config_file, connections_file = find_config_files()
    connections = {}
    default_conn = "default"
    
    # Load from config.toml (has connections.X format)
    if config_file:
        try:
            with open(config_file, "rb") as f:
                config = tomllib.load(f)
            default_conn = config.get("default_connection_name", default_conn)
            for name, params in config.get("connections", {}).items():
                connections[name] = params
        except Exception:
            pass
    
    # Load from connections.toml (has [name] format directly)
    if connections_file:
        try:
            with open(connections_file, "rb") as f:
                conn_config = tomllib.load(f)
            if "default_connection_name" in conn_config:
                default_conn = conn_config["default_connection_name"]
            for name, params in conn_config.items():
                if name != "default_connection_name" and isinstance(params, dict):
                    connections[name] = params
        except Exception:
            pass
    
    return connections, default_conn


def get_connection_params(name: Optional[str] = None) -> Tuple[Optional[Dict], str]:
    """Get connection parameters by name."""
    connections, default_name = load_connections()
    conn_name = name or default_name
    return connections.get(conn_name), conn_name


def list_connections() -> List[str]:
    """List available connection names."""
    connections, default = load_connections()
    result = []
    for name in sorted(connections.keys()):
        marker = " (default)" if name == default else ""
        result.append(f"{name}{marker}")
    return result


# ---------------------------------------------------------------------------
# JWT Generation for Private Key Authentication
# ---------------------------------------------------------------------------

def generate_jwt_token(account: str, user: str, private_key_path: str, private_key_pwd: str = None) -> Optional[str]:
    """Generate a JWT token for Snowflake authentication using a private key."""
    if not HAS_CRYPTO:
        print(f"{YELLOW}cryptography package not installed, cannot use private key auth{RESET}")
        return None
    
    try:
        key_path = Path(private_key_path).expanduser()
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=private_key_pwd.encode() if private_key_pwd else None,
                backend=default_backend()
            )
        
        # Get public key fingerprint
        public_key = private_key.public_key()
        public_key_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        public_key_fp = "SHA256:" + base64.b64encode(sha256_hash).decode()
        
        # Build JWT manually (avoid PyJWT dependency)
        account_upper = account.upper().replace("-", "_").split(".")[0]
        qualified_user = f"{account_upper}.{user.upper()}"
        
        now = int(time.time())
        payload = {
            "iss": f"{qualified_user}.{public_key_fp}",
            "sub": qualified_user,
            "iat": now,
            "exp": now + 3600,  # 1 hour
        }
        
        # Simple JWT encoding (header.payload.signature)
        header = {"alg": "RS256", "typ": "JWT"}
        
        def b64url(data: bytes) -> str:
            return base64.urlsafe_b64encode(data).rstrip(b"=").decode()
        
        header_b64 = b64url(json.dumps(header, separators=(",", ":")).encode())
        payload_b64 = b64url(json.dumps(payload, separators=(",", ":")).encode())
        message = f"{header_b64}.{payload_b64}".encode()
        
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import padding
        
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())
        signature_b64 = b64url(signature)
        
        return f"{header_b64}.{payload_b64}.{signature_b64}"
    except Exception as e:
        print(f"{RED}Failed to generate JWT: {e}{RESET}")
        return None


# ---------------------------------------------------------------------------
# Workload Identity Federation (WIF) - Cloud Provider Token Fetching
# ---------------------------------------------------------------------------

def fetch_wif_token(provider: str = "auto") -> Optional[str]:
    """Fetch a token from cloud provider metadata service for WIF authentication.
    
    Supports: aws, azure, gcp, or 'auto' to detect automatically.
    """
    endpoints = {
        "gcp": {
            "url": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            "headers": {"Metadata-Flavor": "Google"},
            "token_field": "access_token",
        },
        "azure": {
            "url": "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
            "headers": {"Metadata": "true"},
            "token_field": "access_token",
        },
        "aws": {
            # AWS IMDSv2 requires a session token first
            "token_url": "http://169.254.169.254/latest/api/token",
            "token_headers": {"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            "url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "token_field": "Token",
        },
    }
    
    def try_provider(name: str) -> Optional[str]:
        cfg = endpoints.get(name)
        if not cfg:
            return None
        
        try:
            if name == "aws":
                # IMDSv2: get session token first
                token_req = urllib.request.Request(cfg["token_url"], method="PUT", headers=cfg["token_headers"])
                session_token = urllib.request.urlopen(token_req, timeout=2).read().decode()
                
                # Get role name
                role_req = urllib.request.Request(cfg["url"], headers={"X-aws-ec2-metadata-token": session_token})
                role_name = urllib.request.urlopen(role_req, timeout=2).read().decode().strip()
                
                # Get credentials
                cred_url = cfg["url"] + role_name
                cred_req = urllib.request.Request(cred_url, headers={"X-aws-ec2-metadata-token": session_token})
                creds = json.loads(urllib.request.urlopen(cred_req, timeout=2).read())
                return creds.get(cfg["token_field"])
            else:
                req = urllib.request.Request(cfg["url"], headers=cfg.get("headers", {}))
                resp = json.loads(urllib.request.urlopen(req, timeout=2).read())
                return resp.get(cfg["token_field"])
        except Exception:
            return None
    
    if provider == "auto":
        for p in ["gcp", "azure", "aws"]:
            token = try_provider(p)
            if token:
                print(f"{DIM}WIF: detected {p.upper()} environment{RESET}")
                return token
        return None
    else:
        return try_provider(provider)


SYSTEM_PROMPT = """You are a coding assistant with access to these tools:
- bash: Execute shell commands
- read: Read file contents  
- write: Write to files
- edit: Edit files
- glob: Find files by pattern
- grep: Search file contents
- web_search: Search the web (server-side)
- snowflake_sql_execute: Run SQL queries against Snowflake (server-side, ONE statement per call - split multi-statement queries)

When the user asks you to run a command, read a file, or perform any action you have a tool for, USE THE TOOL. Do not just explain what would happen - actually call the tool.

Current working directory: {cwd}

{snowflake_context}"""

SNOWFLAKE_CONTEXT_PROMPT = """Snowflake Connection:
- Account: {account}
- User: {user}
- Default Warehouse: {warehouse}
- Default Database: {database}
- Default Schema: {schema}
- Current Role: {role}
- Snowflake Version: {version}

Available Databases: {databases}

IMPORTANT: When a database and schema are set (not "(not set)"), you MUST query ONLY that database/schema unless explicitly asked otherwise. Use fully qualified names like DATABASE.SCHEMA.TABLE. Do NOT list tables from all databases when a specific context is set."""

REFLECT_PROMPT = """Review your previous response. Did you fully complete the user's request? Check for:
- Errors in tool outputs (SQL errors, file not found, etc.)
- Incomplete results or missing information
- Incorrect assumptions about the data or context

If everything looks correct, respond with just: LGTM
If there are issues to fix, explain briefly and take corrective action."""


def read_file(args: Dict) -> str:
    path = args.get("path") or args.get("file_path")
    if not path:
        return "error: path required"
    lines = open(path).readlines()
    offset, limit = args.get("offset", 0), args.get("limit", len(lines))
    return "".join(f"{offset + i + 1:4}| {l}" for i, l in enumerate(lines[offset:offset + limit]))


def write_file(args: Dict) -> str:
    path = args.get("path") or args.get("file_path")
    if not path:
        return "error: path required"
    open(path, "w").write(args["content"])
    return "ok"


def edit_file(args: Dict) -> str:
    path = args.get("path") or args.get("file_path")
    if not path:
        return "error: path required"
    text = open(path).read()
    old, new = args.get("old") or args.get("old_string", ""), args.get("new") or args.get("new_string", "")
    if old not in text:
        return "error: old_string not found"
    if not args.get("all") and not args.get("replace_all") and text.count(old) > 1:
        return f"error: old_string appears {text.count(old)} times, use all=true"
    open(path, "w").write(text.replace(old, new) if args.get("all") or args.get("replace_all") else text.replace(old, new, 1))
    return "ok"


def glob_files(args: Dict) -> str:
    pat = (args.get("path", ".") + "/" + args["pattern"]).replace("//", "/")
    files = sorted(globlib.glob(pat, recursive=True), 
                   key=lambda f: os.path.getmtime(f) if os.path.isfile(f) else 0, reverse=True)
    return "\n".join(files[:100]) or "no matches"


def grep_files(args: Dict) -> str:
    pattern, hits = re.compile(args["pattern"]), []
    for fp in globlib.glob(args.get("path", ".") + "/**", recursive=True):
        try:
            for n, line in enumerate(open(fp), 1):
                if pattern.search(line):
                    hits.append(f"{fp}:{n}:{line.rstrip()}")
        except: pass
    return "\n".join(hits[:50]) or "no matches"


def run_bash(args: Dict) -> str:
    proc = subprocess.Popen(args["command"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    try:
        while True:
            line = proc.stdout.readline()
            if not line and proc.poll() is not None: break
            if line:
                print(f"  {DIM}│ {line.rstrip()}{RESET}", flush=True)
                out.append(line)
        proc.wait(timeout=60)
    except subprocess.TimeoutExpired:
        proc.kill()
        out.append("\n(timed out)")
    return "".join(out).strip() or "(empty)"


# Tools that we only support if Snowflake executes them server-side
SERVER_SIDE_TOOLS = {"web_search", "snowflake_sql_execute"}





# Client-side tools: we execute them locally
CLIENT_TOOLS = {
    "read": ("Read file with line numbers", {"path": "string", "offset": "number?", "limit": "number?"}, read_file),
    "write": ("Write content to file", {"path": "string", "content": "string"}, write_file),
    "edit": ("Replace old with new in file", {"path": "string", "old": "string", "new": "string", "all": "boolean?"}, edit_file),
    "glob": ("Find files by pattern", {"pattern": "string", "path": "string?"}, glob_files),
    "grep": ("Search files for regex", {"pattern": "string", "path": "string?"}, grep_files),
    "bash": ("Run shell command", {"command": "string"}, run_bash),
}

# All built-in tool types recognized by Cortex Agent API (server knows schema)
BUILTIN_TOOL_TYPES = {"read", "write", "edit", "glob", "grep", "bash"} | SERVER_SIDE_TOOLS


def build_tools() -> List[Dict]:
    tools = []
    # All built-in tools: type matches name, server knows the schema
    for name in BUILTIN_TOOL_TYPES:
        tools.append({"tool_spec": {"type": name, "name": name}})
    return tools


class CortexAgent:
    """Cortex Agent client with connection management."""
    
    @classmethod
    def from_connection(cls, conn_name: Optional[str] = None, model: str = "auto") -> "CortexAgent":
        """Create agent from a named connection in connections.toml."""
        params, resolved_name = get_connection_params(conn_name)
        if not params:
            raise ValueError(f"Connection '{conn_name or 'default'}' not found in connections.toml")
        
        account = params.get("account")
        user = params.get("user")
        if not account or not user:
            raise ValueError(f"Connection '{resolved_name}' missing account or user")
        
        # Get auth info
        auth = params.get("authenticator", "").upper()
        pat = None
        if auth == "PROGRAMMATIC_ACCESS_TOKEN":
            pat = params.get("token")
            if not pat and params.get("token_file_path"):
                token_path = Path(params["token_file_path"]).expanduser()
                if token_path.exists():
                    pat = token_path.read_text().strip()
        
        warehouse = params.get("warehouse")
        
        agent = cls(
            account=account,
            user=user,
            pat=pat,
            warehouse=warehouse,
            conn_params=params,
            conn_name=resolved_name,
            model=model,
        )
        return agent
    
    def __init__(self, account: str, user: str, pat: Optional[str] = None, 
                 warehouse: str = None, conn_params: Dict = None, conn_name: str = None,
                 model: str = "auto"):
        self.account = account
        self.user = user
        self.pat = pat
        self.warehouse = warehouse
        self.conn_params = conn_params or {}
        self.conn_name = conn_name or "manual"
        self.model = model
        self.token: str = None
        self.messages: List[Dict] = []
        self.snowflake_context: Dict[str, str] = {}
        self._system_prompt_sent: bool = False
        self._pending_context_update: str = None
        self.session_id = str(uuid.uuid4())
        self._sf_conn = None  # Snowflake connector connection (lazy init)
        self._connector_failed = False  # Track if connector init permanently failed
        self.reflect = True  # Self-correction mode (default: on)
        self._max_reflect_iterations = 2  # Max reflection attempts

    @property
    def base_url(self) -> str:
        return f"https://{self.account.lower().replace('_', '-')}.snowflakecomputing.com"

    def authenticate(self) -> bool:
        account_name = self.account.upper().replace("-", "_")
        params = self.conn_params or {}
        auth_type = params.get("authenticator", "").upper()

        # 1. PAT Authentication
        if self.pat:
            body = {"data": {
                "ACCOUNT_NAME": account_name,
                "CLIENT_APP_ID": "nanocortex", "CLIENT_APP_VERSION": "1.0",
                "CLIENT_ENVIRONMENT": {"APPLICATION": "nanocortex", "OS": "Python"},
                "AUTHENTICATOR": "PROGRAMMATIC_ACCESS_TOKEN",
                "LOGIN_NAME": self.user, "TOKEN": self.pat,
                "SESSION_PARAMETERS": {"CLIENT_REQUEST_MFA_TOKEN": False}
            }}
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/session/v1/login-request",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
                if not resp.get("success"):
                    print(f"{RED}Auth failed: {resp.get('message')}{RESET}")
                    return False
                self.token = resp["data"]["token"]
                return True
            except Exception as e:
                print(f"{RED}Auth error: {e}{RESET}")
                return False

        # 2. Private Key / JWT Authentication
        if auth_type == "SNOWFLAKE_JWT" or params.get("private_key_file"):
            pk_file = params.get("private_key_file")
            pk_pwd = params.get("private_key_file_pwd")
            if not pk_file:
                print(f"{RED}private_key_file required for JWT auth{RESET}")
                return False
            
            print(f"{DIM}Generating JWT from private key...{RESET}")
            jwt_token = generate_jwt_token(self.account, self.user, pk_file, pk_pwd)
            if not jwt_token:
                return False
            
            body = {"data": {
                "ACCOUNT_NAME": account_name,
                "CLIENT_APP_ID": "nanocortex", "CLIENT_APP_VERSION": "1.0",
                "CLIENT_ENVIRONMENT": {"APPLICATION": "nanocortex", "OS": "Python"},
                "AUTHENTICATOR": "SNOWFLAKE_JWT",
                "LOGIN_NAME": self.user, "TOKEN": jwt_token,
                "SESSION_PARAMETERS": {"CLIENT_REQUEST_MFA_TOKEN": False}
            }}
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/session/v1/login-request",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
                if not resp.get("success"):
                    print(f"{RED}JWT auth failed: {resp.get('message')}{RESET}")
                    return False
                self.token = resp["data"]["token"]
                return True
            except Exception as e:
                print(f"{RED}JWT auth error: {e}{RESET}")
                return False

        # 3. Workload Identity Federation (WIF) - cloud provider tokens
        if auth_type in ("WIF", "WORKLOAD_IDENTITY"):
            wif_provider = params.get("wif_provider", "auto")
            print(f"{DIM}Fetching WIF token from cloud provider...{RESET}")
            wif_token = fetch_wif_token(wif_provider)
            if not wif_token:
                print(f"{RED}Failed to fetch WIF token. Are you running in a cloud environment?{RESET}")
                return False
            
            body = {"data": {
                "ACCOUNT_NAME": account_name,
                "CLIENT_APP_ID": "nanocortex", "CLIENT_APP_VERSION": "1.0",
                "CLIENT_ENVIRONMENT": {"APPLICATION": "nanocortex", "OS": "Python"},
                "AUTHENTICATOR": "OAUTH",
                "LOGIN_NAME": self.user, "TOKEN": wif_token,
                "SESSION_PARAMETERS": {"CLIENT_REQUEST_MFA_TOKEN": False}
            }}
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/session/v1/login-request",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
                if not resp.get("success"):
                    print(f"{RED}WIF auth failed: {resp.get('message')}{RESET}")
                    return False
                self.token = resp["data"]["token"]
                return True
            except Exception as e:
                print(f"{RED}WIF auth error: {e}{RESET}")
                return False

        # 4. External Browser Authentication (default fallback)
            body = {"data": {
                "ACCOUNT_NAME": account_name,
                "CLIENT_APP_ID": "nanocortex", "CLIENT_APP_VERSION": "1.0",
                "CLIENT_ENVIRONMENT": {"APPLICATION": "nanocortex", "OS": "Python"},
                "AUTHENTICATOR": "PROGRAMMATIC_ACCESS_TOKEN",
                "LOGIN_NAME": self.user, "TOKEN": self.pat,
                "SESSION_PARAMETERS": {"CLIENT_REQUEST_MFA_TOKEN": False}
            }}
            try:
                req = urllib.request.Request(
                    f"{self.base_url}/session/v1/login-request",
                    data=json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
                if not resp.get("success"):
                    print(f"{RED}Auth failed: {resp.get('message')}{RESET}")
                    return False
                self.token = resp["data"]["token"]
                return True
            except Exception as e:
                print(f"{RED}Auth error: {e}{RESET}")
                return False

        class _CBState:
            def __init__(self) -> None:
                self.params: Dict[str, str] = {}
                self.path: str = ""
                self.done = threading.Event()

        state = _CBState()

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path == "/favicon.ico":
                    self.send_response(204)
                    self.end_headers()
                    return

                params = urllib.parse.parse_qs(parsed.query)
                flat = {k: (v[0] if v else "") for k, v in params.items()}
                print(f"{DIM}Callback: path={parsed.path} keys={sorted(flat.keys())}{RESET}")
                if flat:
                    state.path = parsed.path
                    state.params.update(flat)
                    state.done.set()

                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<html><body style='font-family:sans-serif'>"
                    b"<h2 style='color:green'>Authentication received.</h2>"
                    b"You can close this tab and return to the terminal."
                    b"</body></html>"
                )

            def log_message(self, fmt, *args):
                return

        server = HTTPServer(("localhost", 0), Handler)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
        t.start()

        try:
            auth_body = {"data": {
                "ACCOUNT_NAME": account_name,
                "LOGIN_NAME": self.user,
                "PORT": 443,
                "PROTOCOL": "https",
                "AUTHENTICATOR": "EXTERNALBROWSER",
                "BROWSER_MODE_REDIRECT_PORT": str(port),
            }}
            req = urllib.request.Request(
                f"{self.base_url}/session/authenticator-request",
                data=json.dumps(auth_body).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp = json.loads(urllib.request.urlopen(req, timeout=30).read())
            if not resp.get("success"):
                print(f"{RED}External auth failed: {resp.get('message')}{RESET}")
                return False

            data = resp.get("data") or {}
            sso_url = data.get("ssoUrl")
            proof_key = data.get("proofKey")
            if not sso_url or not proof_key:
                print(f"{RED}External auth failed: missing ssoUrl/proofKey{RESET}")
                return False

            print(f"{YELLOW}External browser authentication required.{RESET}")
            print(f"{DIM}Opening browser for SSO...{RESET}")
            webbrowser.open(sso_url, new=1, autoraise=True)

            def _get_param_ci(d: Dict[str, str], names) -> Optional[str]:
                lower = {k.lower(): v for k, v in d.items()}
                for n in names:
                    v = lower.get(n.lower())
                    if v:
                        return v
                return None

            if not state.done.wait(timeout=180):
                print(f"{RED}Timed out waiting for browser redirect to localhost:{port}{RESET}")
                return False

            token = _get_param_ci(state.params, ["token"])
            if not token:
                keys = sorted(state.params.keys())
                print(f"{RED}Browser callback missing token{RESET}")
                print(f"{DIM}Callback path={state.path or '/'} keys={keys}{RESET}")
                return False

            request_id = str(uuid.uuid4())
            exchange_url = f"{self.base_url}/session/v1/login-request?requestId={request_id}&request_guid={uuid.uuid4()}"
            exchange_body = {"data": {
                "ACCOUNT_NAME": account_name,
                "CLIENT_APP_ID": "nanocortex", "CLIENT_APP_VERSION": "1.0",
                "CLIENT_ENVIRONMENT": {"APPLICATION": "nanocortex", "OS": "Python"},
                "AUTHENTICATOR": "EXTERNALBROWSER",
                "LOGIN_NAME": self.user,
                "TOKEN": token,
                "PROOF_KEY": proof_key,
                "SESSION_PARAMETERS": {"CLIENT_REQUEST_MFA_TOKEN": False}
            }}

            req2 = urllib.request.Request(
                exchange_url,
                data=json.dumps(exchange_body).encode(),
                headers={"Content-Type": "application/json"},
            )
            resp2 = json.loads(urllib.request.urlopen(req2, timeout=30).read())
            if not resp2.get("success"):
                print(f"{RED}External auth exchange failed: {resp2.get('message')}{RESET}")
                return False
            self.token = resp2["data"]["token"]
            return True
        except Exception as e:
            print(f"{RED}Auth error: {e}{RESET}")
            return False
        finally:
            try:
                server.shutdown()
            except Exception:
                pass
            try:
                server.server_close()
            except Exception:
                pass

    def _stream(self, body: Dict, timeout: int = 180) -> Iterator[Dict]:
        req = urllib.request.Request(
            f"{self.base_url}/api/v2/cortex/agent:run",
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "text/event-stream",
                "Authorization": f'Snowflake Token="{self.token}"',
            },
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        event_type = None
        for raw_line in resp:
            line = raw_line.decode("utf-8").strip()
            if not line:
                continue
            if line.startswith("event:"):
                event_type = line.split(":", 1)[1].strip()
                continue
            if line.startswith("data:"):
                data = line.split(":", 1)[1].strip()
                if not data or data == "[DONE]":
                    continue
                try:
                    evt = json.loads(data)
                except Exception:
                    continue
                evt["_type"] = event_type
                yield evt

    def execute_sql_direct(self, sql: str, timeout: int = 60) -> str:
        """Execute SQL directly via Snowflake REST API (client-side execution)."""
        request_id = str(uuid.uuid4())
        query_url = f"{self.base_url}/queries/v1/query-request?requestId={request_id}&request_guid={uuid.uuid4()}"
        
        body = {
            "disableOfflineChunks": False,
            "sqlText": sql,
            "queryContextDTO": {"entries": []},
        }
        
        req = urllib.request.Request(
            query_url,
            data=json.dumps(body).encode(),
            headers={
                "Content-Type": "application/json",
                "Accept": "application/snowflake",
                "Authorization": f'Snowflake Token="{self.token}"',
            },
        )
        
        try:
            resp = urllib.request.urlopen(req, timeout=timeout)
            result = json.loads(resp.read())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else str(e)
            try:
                error_json = json.loads(error_body)
                msg = error_json.get("message") or error_body
            except:
                msg = error_body
            return f"error: {msg}"
        except Exception as e:
            return f"error: {e}"
        
        if not result.get("success"):
            return f"error: {result.get('message', 'SQL execution failed')}"
        
        data = result.get("data", {})
        rowset = data.get("rowset", [])
        rowtype = data.get("rowtype", [])
        
        if not rowset:
            return "Query executed successfully. No rows returned."
        
        col_names = [col.get("name", f"col{i}") for i, col in enumerate(rowtype)]
        lines = [" | ".join(col_names)]
        lines.append("-" * len(lines[0]))
        for row in rowset[:100]:
            lines.append(" | ".join(str(v) if v is not None else "null" for v in row))
        
        if len(rowset) > 100:
            lines.append(f"... ({len(rowset) - 100} more rows)")
        
        return "\n".join(lines)

    def _build_coding_agent_config(self, use_web_search_passthrough: bool = False) -> Dict:
        """Build the CodingAgent experimental config block."""
        account_locator = self.account.upper().replace("-", "_")
        return {
            "UserID": self.user.split("@")[0],
            "SessionID": self.session_id,
            "Temperature": 1,
            "SystemPromptInternal": {
                "Prompt": "",
                "Attributes": {
                    "WorkingDirectory": os.getcwd(),
                    "IsGitRepo": os.path.isdir(os.path.join(os.getcwd(), ".git")),
                    "Platform": "darwin",
                    "ArtifactDirectory": os.getcwd(),
                    "CanCreateFiles": True,
                    "OSVersion": sys.platform,
                    "AgentVersion": "1.0.0",
                    "AgentVersionLabel": "nanocortex",
                    "SnovaVersion": "1.0.0",
                    "AgentIdentity": "nanocortex",
                    "AgentDescription": "minimal cortex agent client",
                },
                "Version": "v2",
                "FullOverride": False,
            },
            "UseWebSearchPassthrough": use_web_search_passthrough,
            "PrivateMode": False,
            "OriginApplication": "snova",
            "OriginApplicationVersion": "1.0.0",
            "SessionAccountLocators": [account_locator],
            "CurrentSqlAccountLocator": account_locator,
        }

    def _get_sf_connection(self):
        """Get or create a Snowflake connector connection using conn_params."""
        if not HAS_SF_CONNECTOR:
            return None
        if self._connector_failed:
            return None  # Don't retry if we already failed
        if self._sf_conn is not None:
            try:
                self._sf_conn.cursor().execute("SELECT 1")
                return self._sf_conn
            except:
                self._sf_conn = None
        
        try:
            kwargs = {
                "account": self.account,
                "user": self.user,
            }
            
            # Use conn_params if available for full auth flexibility
            params = self.conn_params
            auth = params.get("authenticator", "").upper() if params else ""
            
            if auth == "EXTERNALBROWSER":
                # Let connector do its own browser auth (separate from Agent API auth)
                kwargs["authenticator"] = "externalbrowser"
            elif auth == "PROGRAMMATIC_ACCESS_TOKEN":
                # PAT is used as password (per Snowflake docs)
                token = params.get("token")
                if not token and params.get("token_file_path"):
                    token_path = Path(params["token_file_path"]).expanduser()
                    if token_path.exists():
                        token = token_path.read_text().strip()
                if token:
                    kwargs["password"] = token
            elif params and params.get("password"):
                kwargs["password"] = params["password"]
            elif params and params.get("private_key_file"):
                kwargs["private_key_file"] = str(Path(params["private_key_file"]).expanduser())
                if params.get("private_key_file_pwd"):
                    kwargs["private_key_file_pwd"] = params["private_key_file_pwd"]
            elif self.pat:
                # Fallback: use PAT as password
                kwargs["password"] = self.pat
            else:
                # Default: external browser
                kwargs["authenticator"] = "externalbrowser"
            
            # Optional connection params
            for key in ("warehouse", "database", "schema", "role"):
                val = params.get(key) if params else None
                if not val and key == "warehouse":
                    val = self.warehouse
                if val:
                    kwargs[key] = val
            
            self._sf_conn = snowflake.connector.connect(**kwargs)
            return self._sf_conn
        except Exception as e:
            self._connector_failed = True
            # Debug: show what auth method was attempted
            auth_method = kwargs.get("authenticator", "default")
            print(f"{DIM}  (connector failed with {auth_method} auth: {e}; using REST API){RESET}")
            return None

    def sql_execute(self, sql: str, description: str = "") -> str:
        """Execute SQL via Snowflake connector (preferred) or REST API (fallback)."""
        conn = self._get_sf_connection()
        if conn:
            return self._sql_execute_connector(conn, sql)
        return self.execute_sql_direct(sql)
    
    def _sql_execute_connector(self, conn, sql: str) -> str:
        """Execute SQL using the Snowflake Python connector."""
        try:
            cursor = conn.cursor()
            cursor.execute(sql)
            results = cursor.fetchall()
            
            # Check if this was a context-changing command
            sql_upper = sql.strip().upper()
            if sql_upper.startswith(("USE DATABASE", "USE SCHEMA", "USE ROLE", "USE WAREHOUSE")):
                self._refresh_context_after_use()
            
            if not results:
                return "Query executed successfully. No rows returned."
            
            columns = [desc[0] for desc in cursor.description]
            lines = [" | ".join(columns)]
            lines.append("-" * len(lines[0]))
            for row in results[:100]:
                lines.append(" | ".join(str(v)[:50] if v is not None else "null" for v in row))
            
            if len(results) > 100:
                lines.append(f"... ({len(results) - 100} more rows)")
            
            return "\n".join(lines)
        except Exception as e:
            return f"error: {e}"

    def _refresh_context_after_use(self):
        """Refresh snowflake_context after USE DATABASE/SCHEMA/ROLE/WAREHOUSE commands."""
        try:
            conn = self._sf_conn
            if not conn:
                return
            cursor = conn.cursor()
            cursor.execute("SELECT CURRENT_WAREHOUSE(), CURRENT_DATABASE(), CURRENT_SCHEMA(), CURRENT_ROLE()")
            row = cursor.fetchone()
            if row:
                self.snowflake_context["warehouse"] = row[0] if row[0] else "(not set)"
                self.snowflake_context["database"] = row[1] if row[1] else "(not set)"
                self.snowflake_context["schema"] = row[2] if row[2] else "(not set)"
                self.snowflake_context["role"] = row[3] if row[3] else "(not set)"
        except Exception:
            pass

    def fetch_snowflake_context(self) -> Dict[str, str]:
        """Fetch current Snowflake context (warehouse, database, schema, role, version, databases)."""
        context = {
            "account": self.account,
            "user": self.user,
            "warehouse": self.warehouse or "(not set)",
            "database": "(not set)",
            "schema": "(not set)",
            "role": "(not set)",
            "version": "(unknown)",
            "databases": "(not fetched)",
        }
        
        try:
            result = self.sql_execute(
                "SELECT CURRENT_WAREHOUSE(), CURRENT_DATABASE(), CURRENT_SCHEMA(), CURRENT_ROLE(), CURRENT_VERSION()"
            )
            lines = [l.strip() for l in result.strip().split("\n") if l.strip()]
            for line in lines:
                if "|" in line and "CURRENT" not in line.upper() and "---" not in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if len(parts) >= 5:
                        context["warehouse"] = parts[0] if parts[0] and parts[0] != "null" else "(not set)"
                        context["database"] = parts[1] if parts[1] and parts[1] != "null" else "(not set)"
                        context["schema"] = parts[2] if parts[2] and parts[2] != "null" else "(not set)"
                        context["role"] = parts[3] if parts[3] and parts[3] != "null" else "(not set)"
                        context["version"] = parts[4] if parts[4] and parts[4] != "null" else "(unknown)"
                        break
        except Exception as e:
            print(f"{DIM}  (context query failed: {e}){RESET}")
        
        try:
            db_result = self.sql_execute("SHOW DATABASES")
            db_names = []
            for line in db_result.strip().split("\n"):
                if "|" in line and "name" not in line.lower() and "---" not in line:
                    parts = [p.strip() for p in line.split("|") if p.strip()]
                    if parts:
                        db_names.append(parts[0])
            if db_names:
                context["databases"] = ", ".join(db_names[:20])
                if len(db_names) > 20:
                    context["databases"] += f" (and {len(db_names) - 20} more)"
        except Exception as e:
            print(f"{DIM}  (database list failed: {e}){RESET}")
        
        return context

    def web_search_server(self, query: str) -> str:
        account_locator = self.account.upper().replace("-", "_")
        body = {
            "messages": [{"role": "user", "content": [{"type": "text", "text": query}]}],
            "model": self.model,
            "stream": True,
            "origin_application": "coding_agent",
            "tools": [{"tool_spec": {"type": "web_search", "name": "web_search"}}],
            "tool_choice": {"type": "auto"},
            "tool_resources": {"web_search": {"api_mode": "grounding", "max_results": 10}},
            "experimental": {
                "UseLegacyAnswersToolNames": False,
                "ResponseSchemaVersion": "v2",
                "EnableSingleAgentOrchestration": True,
                "EnableFunctionCallAPIForPlanning": True,
                "ReasoningAgentFlowType": "simple",
                "StopCondition": {"NumSteps": 15},
                "Canary": False,
                "ThinkingEffort": "medium",
                "UseAdaptiveThinking": True,
                "Enable1MContextModel": False,
                "EnableStepTrace": True,
                "CodingAgent": self._build_coding_agent_config(use_web_search_passthrough=True),
            },
        }

        tool_use = None
        tool_result_json = None
        for evt in self._stream(body, timeout=180):
            if evt.get("_type") == "error":
                raise RuntimeError(evt.get("message") or "server-side web_search failed")
            if evt.get("_type") == "response.tool_use" and evt.get("name") == "web_search":
                tool_use = evt
            if evt.get("_type") == "response.tool_result" and evt.get("type") == "web_search":
                for item in evt.get("content", []):
                    if "json" in item:
                        tool_result_json = item["json"]
                        break

        if tool_result_json is None:
            cse = None if not tool_use else tool_use.get("client_side_execute")
            raise RuntimeError(f"web_search returned no tool_result (client_side_execute={cse})")
        return json.dumps(tool_result_json)

    def _call(self) -> Iterator[Dict]:
        account_locator = self.account.upper().replace("-", "_")
        body = {
            "messages": self.messages, "model": self.model, "stream": True,
            "origin_application": "coding_agent", "tools": build_tools(),
            "tool_choice": {"type": "auto"},
            "experimental": {
                "UseLegacyAnswersToolNames": False,
                "ResponseSchemaVersion": "v2",
                "EnableSingleAgentOrchestration": True,
                "EnableFunctionCallAPIForPlanning": True,
                "ReasoningAgentFlowType": "simple",
                "StopCondition": {"NumSteps": 15},
                "ThinkingEffort": "medium",
                "EnableStepTrace": True,
                "CodingAgent": self._build_coding_agent_config(use_web_search_passthrough=False),
            },
            "tool_resources": {
                "web_search": {
                    "api_mode": "grounding",
                    "max_results": 10
                }
            }
        }
        return self._stream(body)


    def chat(self, user_input: str, _reflect_iteration: int = 0):
        # Include system prompt with first message
        content = [{"type": "text", "text": user_input}]
        is_reflection = _reflect_iteration > 0
        interrupted = False
        
        if not self._system_prompt_sent:
            # Prepend system context on first message
            self._system_prompt_sent = True
            sf_ctx = getattr(self, 'snowflake_context', None) or {}
            snowflake_context_text = SNOWFLAKE_CONTEXT_PROMPT.format(
                account=sf_ctx.get('account', self.account),
                user=sf_ctx.get('user', self.user),
                warehouse=sf_ctx.get('warehouse', self.warehouse or '(not set)'),
                database=sf_ctx.get('database', '(not set)'),
                schema=sf_ctx.get('schema', '(not set)'),
                role=sf_ctx.get('role', '(not set)'),
                version=sf_ctx.get('version', '(unknown)'),
                databases=sf_ctx.get('databases', '(not fetched)'),
            )
            system_text = SYSTEM_PROMPT.format(cwd=os.getcwd(), snowflake_context=snowflake_context_text)
            content.insert(0, {"type": "text", "text": system_text})
        elif self._pending_context_update:
            content.insert(0, {"type": "text", "text": self._pending_context_update})
            self._pending_context_update = None
        
        self.messages.append({"role": "user", "id": f"msg_{uuid.uuid4()}", "content": content})
        while True:
            text_buf, tool_calls, assistant_content = "", [], []
            server_results = {}  # Capture server-provided results
            evt_count = 0
            suppress_output = is_reflection  # Don't show reflection output initially

            try:
                for evt in self._call():
                    evt_count += 1
                    etype = evt.get("_type", "")
                    
                    # Handle both orchestrated (response.text.delta) and non-orchestrated (message.delta) formats
                    if etype == "response.text.delta":
                        txt = evt.get("text", "") or evt.get("delta", {}).get("text", "")
                        text_buf += txt
                        # For reflections, only show if it's not just "LGTM"
                        if not suppress_output:
                            print(txt, end="", flush=True)
                    elif etype == "message.delta":
                        # Non-orchestrated format: delta.content[].text
                        for item in evt.get("delta", {}).get("content", []):
                            if item.get("type") == "text":
                                txt = item.get("text", "")
                                text_buf += txt
                                if not suppress_output:
                                    print(txt, end="", flush=True)

                    elif etype == "response.tool_use":
                        name, inp, tid = evt.get("name"), evt.get("input", {}), evt.get("tool_use_id")
                        client = evt.get("client_side_execute", True)
                        tool_calls.append({"name": name, "input": inp, "id": tid, "client": client})
                        if text_buf: print(); text_buf = ""
                        preview = str(list(inp.values())[0])[:40] if inp else ""
                        color = GREEN if client else MAGENTA
                        tag = "" if client else f" {MAGENTA}[server]{RESET}"
                        print(f"\n{color}⏺ {name}{RESET}({DIM}{preview}{RESET}){tag}")

                    elif etype == "response.tool_result":
                        tid = evt.get("tool_use_id")
                        # Capture server-provided result for later use
                        result_text = ""
                        for item in evt.get("content", []):
                            txt = item.get("text") or json.dumps(item.get("json", {}))
                            result_text += txt
                            print(f"  {DIM}⎿  {txt[:80]}{'...' if len(txt)>80 else ''}{RESET}")
                        if tid and result_text:
                            server_results[tid] = result_text

            except KeyboardInterrupt:
                # User interrupted - allow clarification
                interrupted = True
                print(f"\n{YELLOW}[interrupted]{RESET}")
                if text_buf:
                    assistant_content.append({"type": "text", "text": text_buf + " [interrupted by user]"})
                if assistant_content:
                    self.messages.append({"role": "assistant", "content": assistant_content})
                
                try:
                    clarification = input(f"{YELLOW}Clarify or press Enter to stop: {RESET}").strip()
                    if clarification:
                        # Recursively call chat with the clarification
                        print()
                        self.chat(f"[User interrupted and clarified]: {clarification}", _reflect_iteration=_reflect_iteration)
                        return  # Exit this chat call after the recursive one completes
                    else:
                        return  # Exit cleanly
                except (KeyboardInterrupt, EOFError):
                    return

            if text_buf:
                # For reflection: if response is just LGTM, skip output entirely
                if is_reflection and text_buf.strip().upper() == "LGTM":
                    return  # Silent exit, nothing to fix
                # If we suppressed output but have substantive content, show it now
                if suppress_output and text_buf.strip():
                    print(text_buf)  # Show the actual corrective feedback
                else:
                    print()  # Just add newline after streamed output
                assistant_content.append({"type": "text", "text": text_buf})

            client_results = []
            for tc in tool_calls:
                assistant_content.append({"type": "tool_use", "tool_use": {
                    "tool_use_id": tc["id"], "name": tc["name"], "input": tc["input"]}})
                
                # Check if server already provided result
                if tc["id"] in server_results:
                    result = server_results[tc["id"]]
                    print(f"  {MAGENTA}⎿  [server result received]{RESET}")
                elif tc["client"]:
                    if tc["name"] == "web_search":
                        q = (tc["input"] or {}).get("query") or ""
                        if not q:
                            result = "error: query required"
                        else:
                            try:
                                result = self.web_search_server(q)
                            except Exception as e:
                                result = f"error: {e}"
                        print(f"  {DIM}⎿  {result[:80]}{'...' if len(result)>80 else ''}{RESET}")
                    elif tc["name"] == "snowflake_sql_execute":
                        sql = (tc["input"] or {}).get("sql") or ""
                        if not sql:
                            result = "error: sql required"
                        else:
                            try:
                                result = self.sql_execute(sql)
                            except Exception as e:
                                result = f"error: {e}"
                        print(f"  {DIM}⎿  {result[:80]}{'...' if len(result)>80 else ''}{RESET}")
                    elif tc["name"] in CLIENT_TOOLS:
                        try:
                            result = CLIENT_TOOLS[tc["name"]][2](tc["input"])
                        except Exception as e:
                            result = f"error: {e}"
                        print(f"  {DIM}⎿  {result[:80]}{'...' if len(result)>80 else ''}{RESET}")
                    else:
                        result = f"error: tool '{tc['name']}' not implemented"
                        print(f"  {RED}⎿  {result}{RESET}")
                else:
                    if tc["name"] in SERVER_SIDE_TOOLS:
                        result = f"error: server-side tool '{tc['name']}' returned no tool_result"
                        print(f"  {RED}⎿  {result}{RESET}")
                        client_results.append({"type": "tool_result", "tool_result": {
                            "tool_use_id": tc["id"], "name": tc["name"],
                            "content": [{"type": "text", "text": result}],
                            "status": "error"}})
                        continue
                    print(f"  {DIM}⎿  (server-side){RESET}")
                    continue
                    
                client_results.append({"type": "tool_result", "tool_result": {
                    "tool_use_id": tc["id"], "name": tc["name"],
                    "content": [{"type": "text", "text": result}],
                    "status": "error" if result.startswith("error:") else "success"}})

            if assistant_content:
                self.messages.append({"role": "assistant", "content": assistant_content})
            if client_results:
                self.messages.append({"role": "user", "content": client_results})
                continue
            break
        
        # Self-correction: reflect on output if enabled and not already reflecting
        if self.reflect and not is_reflection and _reflect_iteration < self._max_reflect_iterations:
            # Check if there were any errors in this turn
            last_assistant = self.messages[-1] if self.messages and self.messages[-1].get("role") == "assistant" else None
            if last_assistant:
                print(f"\n{DIM}[reflecting...]{RESET}")
                self.chat(REFLECT_PROMPT, _reflect_iteration=_reflect_iteration + 1)

    def clear(self): self.messages = []


def get_term_width() -> int:
    try:
        return min(os.get_terminal_size().columns, 80)
    except OSError:
        return 80


def main():
    parser = argparse.ArgumentParser(
        description="nanocortex - Snowflake Cortex Agent Coding Assistant",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-c", "--connection",
        help="Connection name from ~/.snowflake/connections.toml (uses default if not specified)"
    )
    parser.add_argument(
        "-l", "--list-connections",
        action="store_true",
        help="List available connections and exit"
    )
    parser.add_argument(
        "-m", "--model",
        default="auto",
        help="Model to use (default: auto). Examples: auto, claude-sonnet-4-6, claude-opus-4-5"
    )
    parser.add_argument(
        "-d", "--database",
        help="Database to USE at startup"
    )
    parser.add_argument(
        "-s", "--schema",
        help="Schema to USE at startup"
    )
    parser.add_argument(
        "-r", "--role",
        help="Role to USE at startup"
    )
    parser.add_argument(
        "-w", "--warehouse",
        help="Warehouse to USE at startup"
    )
    parser.add_argument(
        "-p", "--prompt",
        help="Run a single prompt and exit (non-interactive mode)"
    )
    parser.add_argument(
        "--no-reflect",
        action="store_true",
        help="Disable self-correction/reflection mode (default: enabled)"
    )
    args = parser.parse_args()
    
    if args.list_connections:
        conns = list_connections()
        if conns:
            print(f"{BOLD}Available connections:{RESET}")
            for c in conns:
                print(f"  {c}")
        else:
            print(f"{YELLOW}No connections found in ~/.snowflake/connections.toml{RESET}")
            print(f"\nCreate connections.toml with format:")
            print(f"""
[myconnection]
account = "myorg-myaccount"
user = "myuser"
authenticator = "EXTERNALBROWSER"
warehouse = "MY_WH"
""")
        return
    
    # Try to create agent from connection
    try:
        agent = CortexAgent.from_connection(args.connection, model=args.model)
        conn_name = agent.conn_name
    except ValueError as e:
        # Fallback to environment variables
        account = os.environ.get("SNOWFLAKE_ACCOUNT")
        user = os.environ.get("SNOWFLAKE_USER")
        pat = os.environ.get("SNOWFLAKE_PAT")
        warehouse = os.environ.get("SNOWFLAKE_WAREHOUSE")
        
        if not all([account, user]):
            print(f"""
{BOLD}nanocortex{RESET} - Snowflake Cortex Agent Coding Assistant

{RED}No connection found!{RESET} {e}

Options:
  1. Use ~/.snowflake/connections.toml (recommended):
     {DIM}nanocortex -c myconnection{RESET}
     
     List available: {DIM}nanocortex -l{RESET}
     
  2. Use environment variables:
     export SNOWFLAKE_ACCOUNT="myorg-myaccount"
     export SNOWFLAKE_USER="myuser"
     export SNOWFLAKE_PAT="your_pat"  {DIM}# or use EXTERNALBROWSER{RESET}
     export SNOWFLAKE_WAREHOUSE="warehouse"  {DIM}# optional{RESET}
""")
            return
        
        agent = CortexAgent(account, user, pat, warehouse, model=args.model)
        conn_name = "env"
    
    # Apply reflection setting from CLI
    if args.no_reflect:
        agent.reflect = False

    sep = lambda: print(f"{DIM}{'─' * get_term_width()}{RESET}")
    
    print(f"{BOLD}nanocortex{RESET} | {DIM}Snowflake Cortex Agent | {os.getcwd()}{RESET}")
    print(f"{DIM}Connection: {conn_name} | Account: {agent.account} | User: {agent.user}{RESET}\n")

    print(f"{DIM}Authenticating...{RESET}", end=" ", flush=True)
    if not agent.authenticate(): return
    print(f"{GREEN}✓{RESET}")

    print(f"{DIM}Fetching Snowflake context...{RESET}", end=" ", flush=True)
    try:
        sf_context = agent.fetch_snowflake_context()
        agent.snowflake_context = sf_context
        print(f"{GREEN}✓{RESET}")
        print(f"{DIM}  Role: {sf_context['role']} | DB: {sf_context['database']} | Schema: {sf_context['schema']}{RESET}")
        reflect_status = f"{GREEN}ON{RESET}" if agent.reflect else f"{RED}OFF{RESET}"
        print(f"{DIM}  Warehouse: {sf_context['warehouse']} | Reflect: {reflect_status}{RESET}\n")
    except Exception as e:
        print(f"{YELLOW}⚠ {e}{RESET}")
        agent.snowflake_context = {
            "account": agent.account, "user": agent.user, "warehouse": agent.warehouse or "(not set)",
            "database": "(not set)", "schema": "(not set)", "role": "(not set)",
            "version": "(unknown)", "databases": "(not fetched)"
        }
        print()

    # Apply CLI overrides for role/warehouse/database/schema
    cli_changes = []
    if args.role:
        try:
            agent.execute_sql_direct(f"USE ROLE {args.role.upper()}")
            cli_changes.append(f"Role: {args.role.upper()}")
        except Exception as e:
            print(f"{RED}Failed to set role: {e}{RESET}")
    if args.warehouse:
        try:
            agent.execute_sql_direct(f"USE WAREHOUSE {args.warehouse.upper()}")
            cli_changes.append(f"Warehouse: {args.warehouse.upper()}")
        except Exception as e:
            print(f"{RED}Failed to set warehouse: {e}{RESET}")
    if args.database:
        try:
            agent.execute_sql_direct(f"USE DATABASE {args.database.upper()}")
            cli_changes.append(f"Database: {args.database.upper()}")
        except Exception as e:
            print(f"{RED}Failed to set database: {e}{RESET}")
    if args.schema:
        try:
            agent.execute_sql_direct(f"USE SCHEMA {args.schema.upper()}")
            cli_changes.append(f"Schema: {args.schema.upper()}")
        except Exception as e:
            print(f"{RED}Failed to set schema: {e}{RESET}")
    if cli_changes:
        print(f"{GREEN}⏺ {' | '.join(cli_changes)}{RESET}\n")
        # Refresh context after changes
        try:
            agent.snowflake_context = agent.fetch_snowflake_context()
        except:
            pass

    # Non-interactive mode: run single prompt and exit
    if args.prompt:
        agent.chat(args.prompt)
        print()
        try:
            if agent._sf_conn:
                agent._sf_conn.close()
        except:
            pass
        os._exit(0)

    # Set up readline history for prompt navigation (up/down arrows)
    try:
        readline.set_history_length(MAX_HISTORY)
        if HISTORY_FILE.exists():
            readline.read_history_file(HISTORY_FILE)
    except Exception:
        pass  # History not critical
    
    def save_history():
        try:
            readline.write_history_file(HISTORY_FILE)
        except Exception:
            pass

    def inject_context_change(change_type: str, value: str):
        """Queue a context update to be prepended to the next user message."""
        ctx = agent.snowflake_context
        msg = f"[IMPORTANT CONTEXT UPDATE: {change_type} changed to '{value}'. You MUST now use this context for all queries: Database={ctx.get('database', '(not set)')}, Schema={ctx.get('schema', '(not set)')}, Role={ctx.get('role', '(not set)')}, Warehouse={ctx.get('warehouse', '(not set)')}. Always use fully qualified names like DATABASE.SCHEMA.TABLE when querying.]"
        agent._pending_context_update = msg

    def context_line():
        ctx = agent.snowflake_context
        tw = get_term_width()
        role = ctx.get('role', '?')
        db = ctx.get('database', '?')
        schema = ctx.get('schema', '?')
        wh = ctx.get('warehouse', '?')
        model = agent.model
        # Compact format: Role | DB.Schema | WH | Model
        if db != "(not set)" and schema != "(not set)":
            db_schema = f"{db}.{schema}"
        else:
            db_schema = f"{db}/{schema}" if db != schema else db
        line = f"{role} | {db_schema} | {wh} | {model}"
        return f"{DIM}{line:>{tw}}{RESET}"

    while True:
        try:
            sep()
            print(context_line())
            inp = input(f"{BOLD}{BLUE}❯{RESET} ").strip()
            sep()
            if not inp: continue
            if inp in ("/q", "exit"): break
            if inp == "/c":
                agent.clear()
                print(f"{GREEN}⏺ Conversation cleared{RESET}")
                continue
            
            if inp == "/clear-context" or inp == "/cc":
                agent.clear()
                agent._system_prompt_sent = False
                print(f"{GREEN}⏺ Conversation context cleared{RESET}")
                continue
            
            if inp == "/clear-history" or inp == "/ch":
                readline.clear_history()
                try:
                    HISTORY_FILE.unlink(missing_ok=True)
                except Exception:
                    pass
                print(f"{GREEN}⏺ Prompt history cleared{RESET}")
                continue
            
            if inp == "/reflect" or inp == "/r":
                agent.reflect = not agent.reflect
                status = f"{GREEN}ON{RESET}" if agent.reflect else f"{RED}OFF{RESET}"
                print(f"{GREEN}⏺ Reflection: {status}{RESET}")
                continue
            
            available_models = [
                "auto",
                "claude-sonnet-4-6", "claude-sonnet-4-5", "claude-4-sonnet",
                "claude-opus-4-6", "claude-opus-4-5",
                "openai-gpt-5.2"
            ]
            
            if inp.startswith("/db") and not inp.startswith("/dbs"):
                parts = inp.split(maxsplit=1)
                if len(parts) == 2:
                    db = parts[1].strip().upper()
                    try:
                        agent.execute_sql_direct(f"USE DATABASE {db}")
                        agent.snowflake_context['database'] = db
                        inject_context_change("DATABASE", db)
                        print(f"{GREEN}⏺ Database: {db}{RESET}")
                    except Exception as e:
                        print(f"{RED}Error: {e}{RESET}")
                else:
                    ctx = agent.get_snowflake_context()
                    print(f"{DIM}Current database: {BOLD}{ctx.get('database', '?')}{RESET}")
                    print(f"{DIM}Usage: /db <database_name>{RESET}")
                continue
            
            if inp.startswith("/schema"):
                parts = inp.split(maxsplit=1)
                if len(parts) == 2:
                    schema = parts[1].strip().upper()
                    try:
                        agent.execute_sql_direct(f"USE SCHEMA {schema}")
                        agent.snowflake_context['schema'] = schema
                        inject_context_change("SCHEMA", schema)
                        print(f"{GREEN}⏺ Schema: {schema}{RESET}")
                    except Exception as e:
                        print(f"{RED}Error: {e}{RESET}")
                else:
                    ctx = agent.get_snowflake_context()
                    print(f"{DIM}Current schema: {BOLD}{ctx.get('schema', '?')}{RESET}")
                    print(f"{DIM}Usage: /schema <schema_name>{RESET}")
                continue
            
            if inp.startswith("/role"):
                parts = inp.split(maxsplit=1)
                if len(parts) == 2:
                    role = parts[1].strip().upper()
                    try:
                        agent.execute_sql_direct(f"USE ROLE {role}")
                        agent.snowflake_context['role'] = role
                        inject_context_change("ROLE", role)
                        print(f"{GREEN}⏺ Role: {role}{RESET}")
                    except Exception as e:
                        print(f"{RED}Error: {e}{RESET}")
                else:
                    ctx = agent.get_snowflake_context()
                    print(f"{DIM}Current role: {BOLD}{ctx.get('role', '?')}{RESET}")
                    print(f"{DIM}Usage: /role <role_name>{RESET}")
                continue
            
            if inp.startswith("/warehouse") or inp.startswith("/wh"):
                parts = inp.split(maxsplit=1)
                if len(parts) == 2:
                    wh = parts[1].strip().upper()
                    try:
                        agent.execute_sql_direct(f"USE WAREHOUSE {wh}")
                        agent.snowflake_context['warehouse'] = wh
                        inject_context_change("WAREHOUSE", wh)
                        print(f"{GREEN}⏺ Warehouse: {wh}{RESET}")
                    except Exception as e:
                        print(f"{RED}Error: {e}{RESET}")
                else:
                    ctx = agent.get_snowflake_context()
                    print(f"{DIM}Current warehouse: {BOLD}{ctx.get('warehouse', '?')}{RESET}")
                    print(f"{DIM}Usage: /warehouse <wh_name> (or /wh){RESET}")
                continue
            
            if inp.startswith("/model") or (inp.isdigit() and 1 <= int(inp) <= len(available_models)):
                if inp.isdigit():
                    idx = int(inp) - 1
                    agent.model = available_models[idx]
                    print(f"{GREEN}⏺ Model: {agent.model}{RESET}")
                    continue
                parts = inp.split(maxsplit=1)
                if len(parts) == 2:
                    model_input = parts[1].strip()
                    if model_input.isdigit():
                        idx = int(model_input) - 1
                        if 0 <= idx < len(available_models):
                            agent.model = available_models[idx]
                            print(f"{GREEN}⏺ Model: {agent.model}{RESET}")
                        else:
                            print(f"{RED}Invalid selection. Choose 1-{len(available_models)}{RESET}")
                    else:
                        agent.model = model_input
                        print(f"{GREEN}⏺ Model: {agent.model}{RESET}")
                else:
                    print(f"{DIM}Current model: {BOLD}{agent.model}{RESET}")
                    print(f"{DIM}Available models:{RESET}")
                    for i, m in enumerate(available_models, 1):
                        marker = f"{GREEN}●{RESET}" if m == agent.model else " "
                        print(f"  {marker} {i}. {m}")
                    print(f"{DIM}Type number or /model <name>{RESET}")
                continue
            agent.chat(inp)
            print()
        except (KeyboardInterrupt, EOFError): 
            print(f"\n{DIM}Bye!{RESET}")
            break
        except Exception as e: 
            print(f"{RED}Error: {e}{RESET}")
    
    # Save history and cleanup
    save_history()
    try:
        if agent._sf_conn:
            agent._sf_conn.close()
    except:
        pass
    os._exit(0)

if __name__ == "__main__":
    main()
