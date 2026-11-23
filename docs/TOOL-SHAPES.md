# Tool shapes: what the model is shown and what it may send

Normative. Models are not fine-tuned for loom. Where a loom tool does what a widely trained tool does, the
model is shown the trained shape, and a call in any well-known harness's shape is run, not refused. Only
tools with no trained counterpart (the ledger, agents, inbox, stored outputs) keep shapes of their own.

## 1. Presented shape (`[tools] dialect`)

`dialect = "trained"` (default) presents the six file and shell tools with the argument names, units and
defaults of Claude Code, which DeepSeek, Kimi, Qwen, GLM and MiniMax models are tuned against.
`dialect = "loom"` presents loom's own names, as before, for comparison runs. Tool **names** stay loom's
lowercase names in both (`read`, `bash`, …). The dialect is fixed for the life of a session (its tool list
is part of the cached prefix).

| tool | trained dialect arguments (presented) | internal (what the tool runs) |
|---|---|---|
| `read` | `file_path`, `offset` (first line, 1-based), `limit` (number of lines) | `path`, `start`, `end = offset + limit - 1` |
| `write` | `file_path`, `content` | `path`, `content` |
| `edit` | `file_path`, `old_string`, `new_string`, `replace_all`, `edits` [{`old_string`,`new_string`,`replace_all`?}], `patch` | `path`, `old`, `new`, `all`, `edits`, `patch` |
| `bash` | `command`, `description`, `timeout` (milliseconds), `run_in_background`, `cwd`, `idle_timeout_s`, `wake_on`, `wake_every_s` | `command`, `description`, `timeout_s = ceil(timeout/1000)`, `background`, … |
| `grep` | `pattern`, `path`, `glob`, `type`, `output_mode` (`content` \| `files_with_matches` \| `count`, default `files_with_matches`), `-i`, `-n`, `-A`, `-B`, `-C`, `head_limit`, `hidden`, `no_ignore` | `pattern`, `path`, `glob`, `type`, `mode`, `ignore_case`, `before`, `after`, `max`, … |
| `glob` | `pattern`, `path`, `hidden`, `no_ignore` | unchanged |

- `description` (bash) is a short label of what the command does. It is recorded with the call and shown
  to the operator as the row's label; it does not change what runs.
- `edits` applies each replacement in order to the text produced by the previous one; if any one fails
  to match (or matches more than once without `replace_all`), the file is left unchanged and the result
  names the failing entry by index. `patch` stays (unified diff or `*** Begin Patch`), as an alternative.
- `-n` is accepted; line numbers are always shown in `content` mode.
- `type` is a ripgrep file type (`rust`, `py`, `js`, …), resolved with the `ignore` crate's default types.
- `read` and `grep` also accept a stored-output handle as `file_path` / `path` (`out:3f2a…`, as printed in a
  result header): such a call runs `out_read` / `out_grep`. `out_read`/`out_grep` remain for roles that
  have them.
- The descriptions of presented tools are rewritten in the presented names; pack texts and harness notes
  name tools, not argument names, so they read correctly in either dialect.

## 2. Accepted shapes (every dialect)

Before the schema check, a call is brought into loom's internal shape (`crates/loom-tools/src/dialect.rs`). Keys that are presented, and loom's
internal keys, are taken silently. Anything else that maps unambiguously is repaired, and the repair is
said in the result header **in the presented names** (`argument \`old_str\` read as \`old_string\``), so the
model learns the shape it was shown. Anything ambiguous is refused, as before; unknown arguments are
never silently dropped.

**Names.** Matching ignores case and treats `-` as `_` (`Read`, `WEB-FETCH`). Then:

| sent | runs | notes |
|---|---|---|
| `Read`, `read_file`, `view_file`, `open_file`, `cat` | `read` | Gemini `absolute_path`; Gemini 0-based `offset` (0 → line 1, said); Cursor `target_file`, `start_line_one_indexed`, `end_line_one_indexed_inclusive`, `should_read_entire_file` |
| `Write`, `write_file`, `create_file`, `write_to_file` | `write` | `file_text`, `contents`, `text` → `content` |
| `Edit`, `MultiEdit`, `str_replace`, `replace` (Gemini), `edit_file` | `edit` | `old_str`/`new_str`; Gemini `expected_replacements` (>1 → `replace_all`; the count is checked); Cursor `edit_file` with `code_edit` is refused: it is a sketch with elisions, not a replacement |
| `replace_in_file` (Cline) | `edit` | `diff` of SEARCH/REPLACE blocks (`<<<<<<< SEARCH` / `=======` / `>>>>>>> REPLACE`, or `------- SEARCH` / `=======` / `+++++++ REPLACE`) → `edits` |
| `apply_patch` (Codex) | `edit`, `write` | `input` or `patch`, or a bare patch string as the arguments; `*** Update File` → `edit` `patch`, `*** Add File` → `write`; several files: checked first, applied in order, all or none; `*** Delete File` / `*** Move to` are refused (nothing applied) — use `bash` |
| `str_replace_editor`, `str_replace_based_edit_tool`, `text_editor` | by `command` | `view` → `read` (`view_range` [a, b], b = -1 → end of file; a directory → `glob` `*`), `create` → `write` (`file_text`), `str_replace` → `edit`, `insert` → `edit` inserting `new_str` after line `insert_line`, `undo_edit` → refused (no undo) |
| `Bash`, `shell`, `exec_command`, `execute_bash`, `run_shell_command`, `run_terminal_cmd`, `execute_command`, `run_command`, `terminal`, `exec`, `sh` | `bash` | Codex argv `command` [..] (`["bash","-lc",X]` / `["sh","-c",X]` → X, otherwise shell-quoted and joined); `cmd`; `workdir`, `directory`, `dir` → `cwd`; `timeout_ms`; `is_background` → `run_in_background`; Cline `requires_approval` and Cursor `explanation` are accepted and dropped (said) |
| `Grep`, `search_file_content`, `grep_search`, `search_files`, `ripgrep`, `rg`, `search` | `grep` | `query`, `regex` → `pattern`; `include`, `include_pattern`, `file_pattern` → `glob`; `case_sensitive: false` → `-i`; `files_only` → `output_mode` |
| `Glob`, `find_files`, `file_search` | `glob` | Cursor `file_search` `query` → `**/*query*` |
| `LS`, `ls`, `list_dir`, `list_directory`, `list_files` | `glob` | `path` / `relative_workspace_path` / `dir_path`; pattern `*`, or `**/*` when `recursive` |
| `WebFetch`, `fetch`, `fetch_url` | `web_fetch` | `prompt` is accepted and said to be unused (the page itself is returned); Gemini `web_fetch` with only `prompt`: the first URL in it |
| `TodoWrite`, `todo_write`, `write_todos`, `update_plan` | `plan` | `todos` [{`content`\|`description`, `status`, `activeForm`?, `id`?}], Codex `plan` [{`step`, `status`}] and `explanation` → `steps` |
| `BashOutput`, `get_job_output` | `job_wait` | `bash_id`, `shell_id`, `job_id`, `id` → `job`; waits 0 s; `filter` is refused |
| `KillShell`, `KillBash`, `kill_job` | `job_kill` | same id keys |
| `Task`, `Agent`, `subagent`, `spawn_agent`, `dispatch_agent`, `delegate` | `agent_spawn` | `prompt` → `question`; `subagent_type` → `role` (a name that is not a role of the pack is refused as today, listing the roles); `description` → `title` (new optional argument: the operator's label; default the question cut to 80 characters) |
| `AskUserQuestion`, `ask_followup_question`, `ask_user_question` | `ask_user` | one question: its text and option labels; several: one numbered question, no options |
| `attempt_completion`, `complete_task`, `task_complete` | `finish` | `result`, `message` → `answer` (also for `finish` itself) |
| `think` | (none) | answered `ok` with "Noted." and no effect; it is a scratchpad in OpenHands and Claude tool use |

A name that maps to a tool the role does not have is refused as today, naming the loom tool
("`Task` runs `agent_spawn`, which this role does not have").

**`plan` with statuses.** Items may carry `status` in either vocabulary: `pending`/`todo`,
`in_progress`/`doing`, `completed`/`done`, `cancelled`/`dropped`. A `plan` call whose step texts match the
current plan's (exactly, after trimming) keeps those steps' ids and evidence and only applies the
statuses; this is the TodoWrite pattern of resending the whole list. A call that changes the texts sets a
new plan, with the given statuses.

**`timeout` units.** `bash` `timeout` is milliseconds when it is 1000 or more. Below 1000 it is read as
seconds (OpenHands and older loom traces send seconds), and the result says so. A timeout above the
maximum is clamped and said.

## 3. Records and the UI

The `tool_call` record keeps the arguments exactly as sent; the `tool_result` header carries the repairs.
The UI reads paths from `path`, `file_path`, `absolute_path` and `target_file`, shows `description` as the
row label (the command stays visible beside it), and shows a mapped call under the loom tool it ran.
