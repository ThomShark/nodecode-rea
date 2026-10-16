# nodecode-rea

REA - **Reverse Engineer Anything** - inside Nodecode.

REA is an npm package, `rea-agents`: one CLI and one MCP server whose catalog is a few hundred
reverse-engineering tools - Ghidra, rizin, apktool, jadx, adb, Playwright, Frida and the rest, each
wrapping one analysis step. This cell registers that server with Nodecode's `mcp` cell, so the tools
arrive as the ordinary MCP vocabulary and nothing new has to be learned.

Nothing of REA is vendored here. This folder is one file of Lisp that writes one config entry.

## What it needs

| | |
| --- | --- |
| Node | 22.19 or newer (24 or newer is what REA asks for) |
| REA | optional: with `rea` on PATH it is used directly, otherwise the server runs `npx -y rea-agents@latest mcp` |
| Ghidra | optional, and the only engine REA ships an integration for in this cell |

## Install

```sh
nodecode add nc://rea        # this cell, once it is on the hub
git clone <this repository> ~/.nodecode/cells/nodecode-rea   # or by hand
```

A folder under `~/.nodecode/cells/` is on; Nodecode loads it at the next launch. With Nodecode
running, `nodecode add` turns it on at once in every attached shell.

At its first start in a home whose config has no `mcp.servers.rea`, the cell writes that entry and
starts the `mcp` cell again, so REA is connected without a reboot. `/rea off` puts it back.

## What it adds

| | |
| --- | --- |
| `mcp.servers.rea` | the registration the `mcp` cell reads, pointing at the CLI or at npx |
| `(mcp:rea/TOOL ...)` | every REA tool, in the MCP cell's ordinary vocabulary: `(mcp:tools "rea")` lists them |
| `/rea` | `status`, `on`, `off`, `doctor`, `install`, `skill` |
| `(help :rea)` | the manual the model reads |
| a standing notice | one line: where REA is, and that its tools are `mcp:rea/*` |

The cell also hands the server the two variables the analysis engines read, `GHIDRA_INSTALL_DIR` and
`JAVA_HOME`, detected like this:

1. the setting, if set;
2. the environment, if set;
3. `~/tools/ghidra*` or `~/ghidra*` holding `support/analyzeHeadless` and `Ghidra/application.properties`;
4. the newest directory under `/usr/lib/jvm` holding `bin/javac` - a full JDK, never a runtime.

That last rule matters: Ghidra refuses a JRE, and a plain `java-25-openjdk` on Fedora is one. If
Ghidra's or REA's tools say Java is wrong, `/rea doctor` says which is being used and what to install.

## Two doors

| | |
| --- | --- |
| The mcp cell | `(mcp:tools "rea")`, `(mcp:rea/analyze ...)`, `(mcp:call "rea" ...)` - the REA tools Nodecode kept |
| REA's CLI | `(rea:commands)`, `(rea:run "analyze" "/bin/ls" ...)` - every command REA has |

Nodecode's `mcp` client keeps the **first 64 tools** of a server, and REA advertises 207, so the MCP
door holds the catalog's first 64 - the native and PE families, in REA's own order. The CLI door is the
rest: `(rea:commands)` lists REA's 153 commands, and `(rea:run ...)` runs one, with its positional
words first and its options as keywords, answering JSON:

```lisp
(rea:run "doctor")
(rea:run "analyze" "/bin/ls")
(rea:run "decompile" "app.apk" "main" :provider "ghidra")
(rea:commands "javascript")
```

A command REA refuses answers its own error object. Nothing here is REA's code: the cell builds an
argv and reads a file.

## The `rea` section

| Member | Default | Meaning |
| --- | --- | --- |
| `bin` | empty | the `rea` CLI to run; empty means `rea` on PATH, and npx when there is none |
| `version` | `latest` | what npx fetches when no CLI is installed |
| `ghidra_dir` | empty | `GHIDRA_INSTALL_DIR` the server starts with |
| `java_home` | empty | `JAVA_HOME` the server starts with |
| `catalog` | `compact` | what `tools/list` advertises; `full` is REA's own default |
| `register` | `true` | keep `mcp.servers.rea` pointing at REA |
| `timeout_seconds` | `180` | how long one REA tool call may take |

An entry somebody registered by hand is never overwritten: the cell says so in its notice, and
`/rea on` is what replaces it.

### Why the catalog is compact

Nodecode's `mcp` client refuses a frame past **1 MiB** and drops the connection when a server sends
one. REA's tool catalog is the frame that arrives first, and measured at REA 6.5.0 it is:

| Profile | `tools/list` frame | Tools |
| --- | --- | --- |
| REA's default | 3.0 MB | 207 |
| `REA_MCP_OUTPUT_SCHEMA_PROFILE=off` | 0.8 MB | 207 |
| `compact` - that, plus `REA_MCP_INPUT_SCHEMA_PROFILE=compact` | 0.2 MB | 207 |

So the cell starts the server with the compact profile, which is REA's own answer to a client that
caps schema size; every tool is still advertised, and REA still validates each result against its
canonical contract. `catalog: full` asks for REA's default instead - all the annotation prose in the
input schemas - and will not connect to Nodecode's `mcp` cell as it stands.

## /rea

| | |
| --- | --- |
| `status` | where REA is, whether the server is connected and how many tools it has, which engines were found |
| `on` | write the `mcp.servers.rea` entry and start the `mcp` cell again |
| `off` | take that entry out; the cell writes it again at its next start, so keeping it out is `"register": false` |
| `doctor` | REA's own readiness audit, summarized: what fails and how to fix it |
| `install` | `npm i -g rea-agents@latest`, in the background; a notice lands when npm is done |
| `skill` | copy REA's bundled skill into `~/.nodecode/skills/reverse-engineer-anything/` for the skills cell |
| `tools [PATTERN]` | REA's command names, or the ones matching a pattern, with REA's own description |
| `run WORDS...` | one command through the CLI: `/rea run doctor`, `/rea run analyze /bin/ls` |

## Security

A cell runs inside Nodecode with full authority over the host, and so does REA: its tools start
Ghidra headless, debuggers and browsers. This cell adds no authority of its own - it edits one
config entry and runs `rea doctor` - but installing REA means handing the agent that catalog. That is
the point, and it is worth knowing.

REA is MIT-licensed, by its own authors; this cell is MIT too, and carries no REA code.
