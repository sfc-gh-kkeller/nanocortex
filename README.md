# nanocortex

**Minimal Snowflake Cortex Agent CLI. Single Python file, ~1,600 lines.**

A complete coding assistant that demonstrates the Cortex Agent API — authentication, tool orchestration, SSE streaming, and the agentic loop pattern.

## Features

- **Minimal dependencies** — stdlib only; optional `snowflake-connector-python` for SQL execution (falls back to REST API)
- **Multiple auth methods** — PAT, Private Key/JWT, Workload Identity Federation (WIF), External Browser
- **Client-side tools** — `bash`, `read`, `write`, `edit`, `glob`, `grep`, `snowflake_sql_execute`
- **Server-side tools** — `web_search`
- **SSE streaming** with full tool execution loop
- **Self-correction** — reflection mode for automatic error recovery
- **Interrupt & clarify** — `Ctrl+C` to stop and redirect the agent
- **Prompt history** — up/down arrows to navigate previous inputs
- **Context management** — switch database, schema, role, warehouse on the fly

## Requirements

- Python 3.8+
- Snowflake account with Cortex Agent enabled
- One of: PAT token, private key, WIF credentials, or browser auth

## Quick Start

### Using pixi (recommended)

```bash
# Install pixi if you don't have it
curl -fsSL https://pixi.sh/install.sh | bash

# Clone and run (minimal - stdlib only)
git clone https://github.com/sfc-gh-kkeller/nanocortex.git
cd nanocortex
pixi run run -c myconnection

# Or with full dependencies (snowflake-connector, cryptography)
pixi run -e full run -c myconnection
```

### Using pip

```bash
# Minimal (stdlib only)
python nanocortex.py -c myconnection

# With optional dependencies
pip install snowflake-connector-python cryptography
python nanocortex.py -c myconnection
```

### Using connections.toml

```toml
# ~/.snowflake/connections.toml

[myconnection]
account = "myorg-myaccount"
user = "myuser"
authenticator = "PROGRAMMATIC_ACCESS_TOKEN"
token_file_path = "~/.snowflake/pat_token"
warehouse = "COMPUTE_WH"
```

```bash
python nanocortex.py -c myconnection
```

### Using environment variables

```bash
export SNOWFLAKE_ACCOUNT="myorg-myaccount"
export SNOWFLAKE_USER="myuser"
export SNOWFLAKE_PAT="your_pat_token"

python nanocortex.py
```

### With specific context

```bash
python nanocortex.py -c myconnection -d MY_DATABASE -s MY_SCHEMA --role ANALYST
```

## Authentication Methods

| Method | Config |
|--------|--------|
| **PAT** | `authenticator = "PROGRAMMATIC_ACCESS_TOKEN"` + `token_file_path` |
| **Private Key** | `private_key_file = "~/.snowflake/rsa_key.p8"` |
| **WIF** | `authenticator = "WIF"` + `wif_provider = "auto"` (or gcp/azure/aws) |
| **Browser** | `authenticator = "EXTERNALBROWSER"` (default fallback) |

## Commands

| Command | Description |
|---------|-------------|
| `/c` | Clear conversation history |
| `/clear-context`, `/cc` | Clear conversation and reset system prompt |
| `/clear-history`, `/ch` | Clear prompt history |
| `/reflect`, `/r` | Toggle self-correction mode |
| `/db <name>` | Switch database |
| `/schema <name>` | Switch schema |
| `/role <name>` | Switch role |
| `/wh <name>` | Switch warehouse |
| `/model` | Change model |
| `/q`, `exit` | Quit |

## CLI Options

```
-c, --connection    Connection name from connections.toml
-d, --database      Initial database
-s, --schema        Initial schema
--role              Initial role
--warehouse         Initial warehouse
--model             Model to use (default: claude-sonnet-4-6)
--no-reflect        Disable self-correction mode
```

## Tools

### Client-Side (executed locally)

| Tool | Description |
|------|-------------|
| `bash` | Run shell commands |
| `read` | Read file with line numbers |
| `write` | Write content to file |
| `edit` | Replace text in file |
| `glob` | Find files by pattern |
| `grep` | Search files for regex |
| `snowflake_sql_execute` | Execute SQL via connector or REST API |

### Server-Side (executed by Snowflake)

| Tool | Description |
|------|-------------|
| `web_search` | Search the web for current information |

## Example Session

```
nanocortex | Snowflake Cortex Agent
Account: myorg-myaccount | User: myuser | claude-sonnet-4-6

Authenticating... done

────────────────────────────────────────────────────────────────────────────────
> what tables are in the sales schema?
────────────────────────────────────────────────────────────────────────────────

⏺ snowflake_sql_execute
  ⎿  SHOW TABLES IN SCHEMA SALES

| name          | rows    |
|---------------|---------|
| ORDERS        | 1234567 |
| CUSTOMERS     | 50000   |
| PRODUCTS      | 2500    |

[reflecting...]

Found 3 tables in the SALES schema: ORDERS (1.2M rows), CUSTOMERS (50K), and PRODUCTS (2.5K).

────────────────────────────────────────────────────────────────────────────────
> ^C
[interrupted]
Clarify or press Enter to stop: only show me the orders table schema
────────────────────────────────────────────────────────────────────────────────

⏺ snowflake_sql_execute
  ⎿  DESCRIBE TABLE SALES.ORDERS
...
```

## How It Works

1. **Authenticate** — Get session token via PAT, JWT, WIF, or browser OAuth
2. **Send message** — POST to `/api/v2/cortex/agent:run` with SSE streaming
3. **Process events** — Handle `response.text.delta`, `response.tool_use`, `response.tool_result`
4. **Execute tools** — Run client-side tools locally, collect results
5. **Continue loop** — Send tool results back until no more tool calls
6. **Reflect** — Optionally review output and self-correct errors

## Resources

- [Snowflake Cortex Documentation](https://docs.snowflake.com/en/user-guide/snowflake-cortex)
- [Programmatic Access Tokens](https://docs.snowflake.com/en/user-guide/admin-pat)

## License

MIT
