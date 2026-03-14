# nanocortex

**Minimal Snowflake Cortex Agent coding assistant. Single Python file, zero dependencies, ~350 lines.**

Inspired by [nanocode](https://github.com/1rgs/nanocode), but uses Snowflake's Cortex Agent API instead of direct Anthropic API calls.

## Requirements

- Python 3.8+
- Snowflake account with **Cortex Agent orchestration enabled**
- PAT (Programmatic Access Token)

> **Important**: Tool orchestration (the ability for the agent to actually call tools like `bash`, `web_search`, `snowflake_sql_execute`) requires specific account-level features. Without orchestration, nanocortex works as a conversational assistant only. Contact your Snowflake account team to enable Cortex Agent orchestration.

## Features

- **Zero external dependencies** - Uses only Python stdlib
- **PAT authentication** - No browser SSO required, perfect for scripts/CI
- **Server-side tools**: `web_search`, `snowflake_sql_execute` (executed by Snowflake)
- **Client-side tools**: `read`, `write`, `edit`, `glob`, `grep`, `bash`
- **SSE streaming** with multi-turn tool execution loop
- **Conversation history** for multi-turn interactions

## Quick Start

```bash
# Set environment variables
export SNOWFLAKE_ACCOUNT="myorg-myaccount"
export SNOWFLAKE_USER="myuser"
export SNOWFLAKE_PAT="your_pat_token"
export SNOWFLAKE_WAREHOUSE="optional_warehouse"  # optional

# Run
python nanocortex.py
```

### Generating a PAT

**Via Snowflake UI:**
1. Navigate to Admin → Security → Programmatic Access Tokens
2. Click "Generate Token"
3. Set lifetime and copy token

**Via Snow CLI:**
```bash
snow pat generate --lifetime-days 30
```

## Commands

| Command | Description |
|---------|-------------|
| `/c` | Clear conversation history |
| `/q` or `exit` | Quit |

## Tools

### How Tool Orchestration Works

When orchestration is enabled, the Cortex Agent API returns `response.tool_use` events indicating the model wants to call a tool. The flow is:

1. User sends message → Agent decides to use a tool
2. API returns `response.tool_use` with `client_side_execute: true/false`
3. If `client_side_execute: true` → nanocortex runs the tool locally
4. If `client_side_execute: false` → Snowflake already ran it (server-side)
5. Results are sent back → Agent continues or responds

### Server-Side Tools (executed by Snowflake)

| Tool | Description |
|------|-------------|
| `web_search` | Search the web for current information |
| `snowflake_sql_execute` | Execute SQL queries in your Snowflake account |

> **Note**: Tool orchestration requires specific account-level features to be enabled. Contact your Snowflake account team to enable orchestration capabilities. Without orchestration, nanocortex works as a conversational assistant.

### Client-Side (executed locally)

| Tool | Description |
|------|-------------|
| `read` | Read file with line numbers |
| `write` | Write content to file |
| `edit` | Replace text in file |
| `glob` | Find files by pattern |
| `grep` | Search files for regex |
| `bash` | Run shell command |

## Example Session

```
nanocortex | Snowflake Cortex Agent | /Users/kevin/project
Account: myorg-myaccount | User: myuser

Authenticating... ✓

────────────────────────────────────────────────────────────────────────────────
❯ what python files are here?
────────────────────────────────────────────────────────────────────────────────

⏺ glob(**/*.py)
  ⎿  nanocortex.py, test_api.py

Found 2 Python files: nanocortex.py and test_api.py

────────────────────────────────────────────────────────────────────────────────
❯ what's the current bitcoin price?
────────────────────────────────────────────────────────────────────────────────

⏺ web_search(bitcoin price) [server]
  ⎿  {"searchResults": [{"title": "Bitcoin USD", "text": "98,432.15...

Bitcoin is currently trading at approximately $98,432.

────────────────────────────────────────────────────────────────────────────────
❯ query my snowflake account for total row counts by schema
────────────────────────────────────────────────────────────────────────────────

⏺ snowflake_sql_execute [server]
  ⎿  SELECT TABLE_SCHEMA, SUM(ROW_COUNT)...

| SCHEMA | TOTAL_ROWS |
|--------|------------|
| PUBLIC | 1,234,567  |
| RAW    | 9,876,543  |
```

---

# Medium Article: Building a Coding Agent with Snowflake Cortex

## Introduction

AI coding assistants have exploded in popularity. Claude Code, Cursor, Codex—they all share a common architecture: an LLM connected to tools that can read files, execute commands, and interact with external services.

But what if you wanted to build your own? And what if you had access to Snowflake's powerful Cortex Agent API with built-in web search and SQL execution?

In this article, we'll build **nanocortex**: a minimal coding agent in ~200 lines of Python with zero external dependencies. It's inspired by [nanocode](https://github.com/1rgs/nanocode) but leverages Snowflake's Cortex Agent API for:

- **Server-side web search** - No API keys needed, Snowflake handles it
- **Server-side SQL execution** - Query your data warehouse naturally
- **Enterprise-ready auth** - PAT tokens for scripts and CI/CD

## The Cortex Agent API

Snowflake's Cortex Agent API (`/api/v2/cortex/agent:run`) is a powerful endpoint that:

1. Accepts messages in a chat format (similar to OpenAI/Anthropic)
2. Supports tool definitions with automatic tool selection
3. Streams responses via Server-Sent Events (SSE)
4. Can execute certain tools server-side (web_search, SQL)

### Authentication

The API uses Snowflake session tokens. For programmatic access, we use PATs (Programmatic Access Tokens):

```python
def authenticate(self) -> bool:
    body = {"data": {
        "ACCOUNT_NAME": self.account.upper().replace("-", "_"),
        "CLIENT_APP_ID": "nanocortex",
        "AUTHENTICATOR": "PROGRAMMATIC_ACCESS_TOKEN",
        "LOGIN_NAME": self.user,
        "TOKEN": self.pat,
    }}
    req = urllib.request.Request(
        f"{self.base_url}/session/v1/login-request",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json"}
    )
    resp = json.loads(urllib.request.urlopen(req).read())
    self.token = resp["data"]["token"]  # Session token for API calls
    return True
```

**Key insight**: The login endpoint returns both a `token` (session token, ~329 chars) and a `masterToken` (~393 chars). The Agent API requires the **session token**, not the master token.

### Message Format

Messages must use a specific structure with content as a list of typed objects:

```python
{
    "role": "user",
    "id": f"msg_{uuid.uuid4()}",
    "content": [{"type": "text", "text": "What is 2+2?"}]
}
```

### Tool Definitions

Tools use a `tool_spec` wrapper. For built-in tools (bash, read, write, etc.), the server already knows the schema:

**Built-in tools** (server knows the schema):
```python
{"tool_spec": {"type": "bash", "name": "bash"}}
{"tool_spec": {"type": "read", "name": "read"}}
{"tool_spec": {"type": "glob", "name": "glob"}}
```

**Server-side tools** (Snowflake executes):
```python
{"tool_spec": {"type": "web_search", "name": "web_search"}}
{"tool_spec": {"type": "snowflake_sql_execute", "name": "snowflake_sql_execute"}}
```

**Custom tools** (with your own schema):
```python
{
    "tool_spec": {
        "type": "client_mcp",
        "name": "my_custom_tool",
        "description": "What this tool does",
        "input_schema": {
            "type": "object",
            "properties": {"param1": {"type": "string"}},
            "required": ["param1"]
        }
    }
}
```

### The API Request

The key to enabling tool orchestration is the `experimental` section with the `CodingAgent` configuration:

```python
body = {
    "messages": self.messages,
    "model": "auto",
    "stream": True,
    "origin_application": "coding_agent",  # Required!
    "tools": build_tools(),
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
        "CodingAgent": {
            "UserID": user_id,
            "SessionID": session_id,
            "Temperature": 1,
            "PrivateMode": False,
            "OriginApplication": "nanocortex",
            "OriginApplicationVersion": "1.0",
            "SessionAccountLocators": [account],
            "CurrentSqlAccountLocator": account,
        }
    }
}

req = urllib.request.Request(
    f"{self.base_url}/api/v2/cortex/agent:run",
    data=json.dumps(body).encode(),
    headers={
        "Content-Type": "application/json",
        "Accept": "text/event-stream",
        "Authorization": f'Snowflake Token="{self.token}"'
    }
)
```

**Critical fields**:
- `origin_application`: Must be `"coding_agent"`
- `tool_choice`: `{"type": "auto"}` for automatic tool selection
- `experimental.CodingAgent`: **Essential for tool orchestration** - without this section, the model will not call tools!

## SSE Response Handling

The response is a stream of Server-Sent Events:

```
event: response.text.delta
data: {"delta": {"text": "Let me search"}}

event: response.tool_use
data: {"name": "web_search", "input": {"query": "..."}, "tool_use_id": "xyz", "client_side_execute": false}

event: response.tool_result
data: {"content": [{"type": "text", "text": "..."}], "tool_use_id": "xyz"}

event: done
data: {"type": "done"}
```

**Key event types**:
- `response.text.delta` - Incremental text output
- `response.tool_use` - Agent wants to use a tool
- `response.tool_result` - Result from server-side tool execution
- `done` - Stream complete

The `client_side_execute` field tells you whether to run the tool locally:
- `true` → Execute locally and send result back
- `false` → Snowflake already executed it, result follows

## The Agentic Loop

The core loop continues until no more client-side tools need execution:

```python
def chat(self, user_input: str):
    self.messages.append(format_message(user_input))
    
    while True:
        tool_calls, client_results = [], []
        
        for event in self._call():
            if event["_type"] == "response.tool_use":
                tool_calls.append(event)
                if event["client_side_execute"]:
                    result = execute_tool(event["name"], event["input"])
                    client_results.append(result)
        
        # Append assistant response with tool calls
        self.messages.append({"role": "assistant", "content": assistant_content})
        
        # If we have client tool results, continue the loop
        if client_results:
            self.messages.append({"role": "user", "content": client_results})
            continue  # Call API again with results
        
        break  # Done - no more tools to execute
```

## Tool Result Format

When sending tool results back, use this structure:

```python
{
    "type": "tool_result",
    "tool_result": {
        "tool_use_id": "toolu_xyz",
        "name": "bash",
        "content": [{"type": "text", "text": "command output here"}],
        "status": "success"  # or "error"
    }
}
```

## Why Cortex Agent API?

1. **Built-in web search** - No need for Serper, Google, or Bing API keys
2. **Native SQL execution** - Query your Snowflake data warehouse conversationally
3. **Enterprise auth** - PATs, SSO, role-based access
4. **Server-side security** - Sensitive operations execute in Snowflake's secure environment

## Complete Code

The entire implementation is ~200 lines of Python with zero dependencies:

```python
# See nanocortex.py for the full implementation
```

## Extending nanocortex

Ideas for enhancements:

1. **Add more client tools** - git operations, file uploads, image generation
2. **Memory/context** - Persist conversation across sessions
3. **Custom server tools** - Cortex Search, Cortex Analyst semantic models
4. **Streaming output** - Better terminal UI with rich formatting
5. **MCP integration** - Connect to Glean, Atlassian, and other enterprise tools

## Conclusion

Building a coding agent doesn't require thousands of lines of code or complex dependencies. With Snowflake's Cortex Agent API, you get a production-ready foundation with built-in web search, SQL execution, and enterprise authentication.

The key insights:
- Use **session tokens** (not master tokens) for API auth
- Message content must be a **list of typed objects**
- The `experimental.CodingAgent` section is **required for tool orchestration**
- Built-in tools (bash, read, etc.) use `type` matching `name` - no schema needed
- Server-side tools have `client_side_execute: false`
- The agentic loop continues until no client tools need execution

Try it yourself: clone the repo, set your environment variables, and start building!

---

*Kevin Keller is a Staff Product Manager at Snowflake working on Cortex AI and developer tools.*

## Resources

- [Snowflake Cortex Documentation](https://docs.snowflake.com/en/user-guide/snowflake-cortex)
- [nanocode - Original inspiration](https://github.com/1rgs/nanocode)
- [Programmatic Access Tokens](https://docs.snowflake.com/en/user-guide/admin-pat)
