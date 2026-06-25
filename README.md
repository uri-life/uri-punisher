# uri-punisher

`uri-punisher` watches Mastodon local admin accounts and applies cautious,
single-IP preemptive moderation based on AbuseIPDB scores.

This version does not punish IP ranges, ASNs, CIDR prefixes, hosting providers,
or other users sharing the same network. Every IP action targets only the exact
observed address as `/32` or `/128`.

This repository contains code written with the help of AI tools, including large
language models. It has only been partially reviewed, so use it with caution.

## Policy

IP blocks:

| AbuseIPDB score | Mastodon severity | Duration |
| --- | --- | --- |
| `>= 100` | `no_access` | 180 days |
| `>= 90` | `no_access` | 90 days |
| `>= 80` | `no_access` | 30 days |
| `>= 70` | `sign_up_block` | 15 days |
| `>= 60` | `sign_up_block` | 7 days |
| `>= 50` | `sign_up_block` | 3 days |

Account action:

| AbuseIPDB score | Action |
| --- | --- |
| `>= 80` | Permanent `silence` with a Korean warning text about likely IP abuse |

The Mastodon account action is sent with `send_email_notification=true`.

## Configuration

The daemon loads `.env` from the current working directory, while real
environment variables take precedence.

Required variables:

```sh
MASTODON_BASE_URL=https://mastodon.example
MASTODON_ACCESS_TOKEN=...
ABUSEIPDB_API_KEY=...
STATE_DIR=./state
ADMIN_ACCOUNTS=admin,second_admin
```

The Mastodon access token must be a user token with enough moderation
permissions for the admin APIs plus `read:notifications` for mention polling.

Optional variables:

```sh
POLL_INTERVAL_SECONDS=30
FALLBACK_RETRY_SECONDS=300
```

`ADMIN_ACCOUNTS` is a comma- or whitespace-separated list of local admin account
names allowed to issue direct-message commands. DM targets must be bare local
usernames such as `alice`; `@alice` and `alice@example.test` are ignored.

## Run

```sh
uv run uri-punisher --once
uv run uri-punisher
```

If account silence failed because the Mastodon role was missing permission, fix
the role and run:

```sh
uv run uri-punisher --retry-failed-silences
```

The first poll only records the current account and mention notification
cursors. That bootstrap step prevents old local accounts and old direct-message
commands from being processed.

Persistent files under `STATE_DIR`:

- `state.json`: account cursor, notification cursor, and processed account IDs
- `queue.json`: restart-safe retry queue
- `queue_events.jsonl`: queue audit events

## Development

```sh
uv run ruff format --check .
uv run ruff check .
uv run pytest
```
