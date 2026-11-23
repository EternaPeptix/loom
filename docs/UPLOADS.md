# File uploads

Normative. The operator can attach files to a message (composer, new-mission form, `loom send --file`,
`loom run --file`). The model sees them the way chat products present uploads: as files saved at a path it
can read, listed under the message, with small text files shown inline.

## Storage

- `POST /api/uploads?workspace=<abs path>&name=<file name>`, raw body (any `Content-Type`), at most
  `UPLOAD_MAX_BYTES` (32 MiB, the Files viewer cap). The workspace must be an existing directory that is
  not and is not inside the loom home (the session-creation rules and sentences). 201 with
  `{ "path": <abs>, "name": <stored name>, "bytes": n, "mime": <sniffed or given> }`; 400 bad name or
  query, 404 workspace missing, 409 refused workspace, 413 too large.
- Stored at `<workspace>/.loom/uploads/<name>`; the name is the given base name with `/`, `\`, NUL and
  control characters replaced by `_`, leading dots stripped, cut to 120 bytes; if it exists,
  `<stem>-2.<ext>`, `-3`, … The directory is made by the daemon (mode 0700 dirs, 0600 files).
- `<workspace>/.loom` is never writable inside the sandbox and is readable except `oracle-secrets`, so
  every session in the workspace can read an upload and none can change it. Under Bubblewrap, where the
  workspace `.loom` is hidden, `.loom/uploads` is bound read-only (test both sandboxes' rules).
- The Files routes (`/api/sessions/{id}/files`, `/files/lines`) serve `.loom/uploads` and nothing else
  under `.loom`.

## The message

`MessageBody` and `NewSession` gain `attachments: [<abs path>]` (serde default empty; text may then be
empty). Each path must be a regular file directly in `<workspace>/.loom/uploads/` of the session's
workspace (400 otherwise: "Attach files with POST /api/uploads first; {path} is not an upload of this
workspace."). The runtime appends the attachment block to the text before recording the user message (the
record holds exactly what the model reads):

```
<text>

Attached files (saved read-only; read them with `read`):
- /ws/.loom/uploads/report.csv (12.4 KB, text/csv)
- /ws/.loom/uploads/screen.png (231 KB, image/png)
```

A UTF-8 text file of at most 16 KiB is also shown inline, after the list, as
`` `<path>`: `` followed by a fenced block with an info string from its extension. Images and other binary
files are listed only. (Image content parts for vision models are not part of this; the model profile
has no vision flag yet.) Sizes use the UI's units (`12.4 KB`, `3.1 MB`).

The block's first line is fixed text, `Attached files (saved read-only; read them with \`read\`):`, so the
UI can recognise it: it renders the list as file chips (name, size; click opens the file in the Files
tab) and the inline copies collapsed, and Copy on the message copies the text above the block.

## UI

Composer and new-mission form: a paperclip button (file picker, multiple), drop files on the composer or
the transcript, paste files or an image from the clipboard. Each file uploads at once and shows as a chip
(name, size, progress, × to remove; a failed upload shows the daemon's sentence and blocks Send until
removed). The new-mission form uploads only once a workspace is entered. Send is enabled with
attachments and no text. Draft attachments are kept with the draft (tab storage).

## CLI

`loom send <id> [TEXT] --file PATH...` and `loom run ... --file PATH...` upload each file, then send.
