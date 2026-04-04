# Wiabs Guest Feed

Encrypted protobuf feed for guest mode. Updated every 2 hours via GitHub Actions.

## Setup

Add `FEED_ENCRYPTION_KEY` to repository secrets (64-char hex string = 32 bytes AES-256 key).

## Manual run

```bash
pip install -r requirements.txt
FEED_ENCRYPTION_KEY=<key> python scripts/update_feed.py
```
