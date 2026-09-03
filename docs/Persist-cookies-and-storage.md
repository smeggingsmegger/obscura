`--storage-dir` is the legacy cookie-directory option. It persists cookies only.
It does not persist `localStorage`, `sessionStorage`, browser cache, history, or
other origin data.

## CLI

```bash
obscura fetch https://example.com --storage-dir ./obscura-data
obscura fetch https://example.com --storage-dir ./obscura-data
```

The second invocation starts with the cookies left by the first.

## Server

```bash
obscura serve --storage-dir ./obscura-data
```

All CDP sessions read and write to the same directory. Run separate `obscura serve` processes with different `--storage-dir` paths for isolated profiles.

## Layout

Inside `./obscura-data`:

- `cookies.json`: cookie jar with SameSite, expiry, host-only, prefix, and
  partition metadata where available.

The file remains backward-readable, but it is not the recommended multi-tenant
profile format. Inspect it with `jq`:

```bash
jq '.[] | select(.domain == "example.com")' ./obscura-data/cookies.json
```

## When state is written

- On clean process exit (Ctrl-C, SIGTERM).
- At the existing CLI/server clean-save points.

## Login once, scrape many

```bash
obscura serve --storage-dir ./session-1
```

Drive a login flow once via Puppeteer or Playwright. Stop the server. Subsequent
runs against the same `--storage-dir` receive the saved cookies. Sites that also
depend on localStorage need Playwright `storageState` or a trusted embedding
broker.

## Broker profile state

The Rust embedding API exposes direct `BrowserContext::export_portable_state`
and `import_portable_state` operations. They accept an explicit set of granted
HTTPS origins and preserve only expiring/session cookies plus origin-scoped
localStorage. They do not navigate, run page JavaScript, or include
sessionStorage. These methods are not exposed by Obscura MCP or as privileged
CDP commands.

## Multiple identities

```bash
obscura serve --port 9222 --storage-dir ./identity-a
obscura serve --port 9223 --storage-dir ./identity-b
```

## Clear state

Delete the exact profile directory only after stopping the owning process.
