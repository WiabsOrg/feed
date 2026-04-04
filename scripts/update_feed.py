#!/usr/bin/env python3
"""
Scrapes https://t.me/s/wiabsfeed for video posts, resolves original posts
for real author names and titles, encodes as protobuf, encrypts with
AES-256-GCM, and writes feed.bin.

Protobuf wire format (compatible with packages/api/src/proto.ts):

WiabsGuestFeedItem (embedded):
  field 1: cdnUrl      (string)
  field 2: author      (string)
  field 3: duration    (uint32, seconds)
  field 4: title       (string)
  field 5: messageId   (uint32)
  field 6: views       (uint32)
  field 7: date        (string, ISO 8601)

WiabsGuestFeed (top-level):
  field 1: version     (uint32) = 1
  field 2: type        (uint32) = 3  (MSG_TYPE_GUEST_FEED)
  field 3: updatedAt   (string, ISO 8601)
  field 4: items       (repeated len-delim WiabsGuestFeedItem)

Encrypted format: [12 bytes nonce][ciphertext + 16 bytes GCM tag]
"""

import base64
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# Protobuf wire-format primitives (same encoding as proto.ts)
# ---------------------------------------------------------------------------

def write_varint(value: int) -> bytes:
    out = bytearray()
    v = value & 0xFFFFFFFF
    while v > 0x7F:
        out.append((v & 0x7F) | 0x80)
        v >>= 7
    out.append(v)
    return bytes(out)


def write_tag(field_number: int, wire_type: int) -> bytes:
    return write_varint((field_number << 3) | wire_type)


def write_uint32_field(field_number: int, value: int) -> bytes:
    if value == 0:
        return b""
    return write_tag(field_number, 0) + write_varint(value)


def write_string_field(field_number: int, value: str) -> bytes:
    if not value:
        return b""
    encoded = value.encode("utf-8")
    return write_tag(field_number, 2) + write_varint(len(encoded)) + encoded


def write_bytes_field(field_number: int, data: bytes) -> bytes:
    if not data:
        return b""
    return write_tag(field_number, 2) + write_varint(len(data)) + data


# ---------------------------------------------------------------------------
# Protobuf decoder (mirrors proto.ts decodeMessageCaption)
# ---------------------------------------------------------------------------

def base64url_decode(s: str) -> bytes:
    """Decode base64url string (no padding) to bytes."""
    s = s.replace("-", "+").replace("_", "/")
    pad = 4 - len(s) % 4
    if pad != 4:
        s += "=" * pad
    return base64.b64decode(s)


def read_varint(data: bytes, offset: int) -> tuple[int, int]:
    """Read a varint from data at offset, return (value, new_offset)."""
    result = 0
    shift = 0
    pos = offset
    while pos < len(data):
        byte = data[pos]
        result |= (byte & 0x7F) << shift
        pos += 1
        if (byte & 0x80) == 0:
            break
        shift += 7
    return result & 0xFFFFFFFF, pos


def decode_protobuf_fields(data: bytes) -> dict[int, list]:
    """
    Parse raw protobuf wire format into {field_number: [values...]}.
    Supports repeated fields. Varint fields → int, len-delim → bytes.
    """
    fields: dict[int, list] = {}
    pos = 0
    while pos < len(data):
        tag, pos = read_varint(data, pos)
        field_number = tag >> 3
        wire_type = tag & 0x7

        if wire_type == 0:  # varint
            value, pos = read_varint(data, pos)
            fields.setdefault(field_number, []).append(value)
        elif wire_type == 2:  # length-delimited
            length, pos = read_varint(data, pos)
            fields.setdefault(field_number, []).append(data[pos : pos + length])
            pos += length
        elif wire_type == 5:  # 32-bit
            pos += 4
        elif wire_type == 1:  # 64-bit
            pos += 8
        else:
            break
    return fields


def get_string(fields: dict[int, list], num: int) -> str:
    """Get first string value for field number."""
    vals = fields.get(num)
    if not vals or not isinstance(vals[0], (bytes, bytearray)):
        return ""
    return vals[0].decode("utf-8", errors="replace")


def get_uint(fields: dict[int, list], num: int) -> int:
    """Get first varint value for field number."""
    vals = fields.get(num)
    if not vals or not isinstance(vals[0], int):
        return 0
    return vals[0]


MSG_TYPE_FEED_PREVIEW = 2
WIABS_PREFIX = "WIABS:"


def decode_feed_preview(caption: str) -> dict | None:
    """
    Decode a WIABS: caption as FeedPreview (type=2).
    Returns {channelUsername, originalMsgId, title, duration} or None.
    """
    if not caption.startswith(WIABS_PREFIX):
        return None
    try:
        data = base64url_decode(caption[len(WIABS_PREFIX) :])
        fields = decode_protobuf_fields(data)
        msg_type = get_uint(fields, 2)
        if msg_type != MSG_TYPE_FEED_PREVIEW:
            return None
        return {
            "channelUsername": get_string(fields, 3),
            "originalMsgId": get_uint(fields, 4),
            "title": get_string(fields, 7),
            "duration": get_uint(fields, 6),
        }
    except Exception as e:
        print(f"[feed] Failed to decode protobuf: {e}")
        return None


# ---------------------------------------------------------------------------
# Protobuf message encoders
# ---------------------------------------------------------------------------

def encode_guest_feed_item(item: dict) -> bytes:
    return (
        write_string_field(1, item["cdn_url"])
        + write_string_field(2, item["author"])
        + write_uint32_field(3, item["duration"])
        + write_string_field(4, item["title"])
        + write_uint32_field(5, item["message_id"])
        + write_uint32_field(6, item["views"])
        + write_string_field(7, item["date"])
    )


MSG_TYPE_GUEST_FEED = 3


def encode_guest_feed(items: list[dict], updated_at: str) -> bytes:
    parts = (
        write_uint32_field(1, 1)  # version = 1
        + write_uint32_field(2, MSG_TYPE_GUEST_FEED)  # type = 3
        + write_string_field(3, updated_at)
    )
    for item in items:
        item_bytes = encode_guest_feed_item(item)
        parts += write_bytes_field(4, item_bytes)  # repeated field 4
    return parts


# ---------------------------------------------------------------------------
# AES-256-GCM encryption
# ---------------------------------------------------------------------------

def encrypt_feed(data: bytes, key_hex: str) -> bytes:
    key = bytes.fromhex(key_hex)
    if len(key) != 32:
        raise ValueError(f"Key must be 32 bytes, got {len(key)}")
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return nonce + ciphertext  # [12 nonce][ciphertext + 16 tag]


# ---------------------------------------------------------------------------
# Original post resolver — fetches real author name from personal channel
# ---------------------------------------------------------------------------

_channel_cache: dict[str, BeautifulSoup] = {}


def get_channel_page(username: str) -> BeautifulSoup:
    """Fetch and cache t.me/s/{username} page."""
    if username in _channel_cache:
        return _channel_cache[username]

    url = f"https://t.me/s/{username}"
    print(f"[feed]   Fetching original channel: {url}")
    time.sleep(0.5)  # rate limit
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    soup = BeautifulSoup(resp.text, "html.parser")
    _channel_cache[username] = soup
    return soup


def resolve_original_post(channel_username: str, msg_id: int) -> dict:
    """
    Fetch the original post from the author's personal channel.
    Returns {"author": str, "title": str} with real values, or empty strings.
    """
    result = {"author": "", "title": ""}
    try:
        soup = get_channel_page(channel_username)
        selector = f'.tgme_widget_message[data-post="{channel_username}/{msg_id}"]'
        msg = soup.select_one(selector)
        if not msg:
            print(f"[feed]   Post {channel_username}/{msg_id} not found on page")
            return result

        # Author from signature profile
        author_el = msg.select_one(".tgme_widget_message_from_author")
        if author_el:
            result["author"] = author_el.get_text(strip=True)

        # Title from protobuf caption (type=1 EncryptedVideo, field 4 = title)
        caption_el = msg.select_one(".js-message_text")
        if caption_el:
            caption_text = caption_el.get_text(strip=True)
            if caption_text.startswith(WIABS_PREFIX):
                try:
                    data = base64url_decode(caption_text[len(WIABS_PREFIX) :])
                    fields = decode_protobuf_fields(data)
                    title = get_string(fields, 4)  # field 4 = title in EncryptedVideo
                    if title:
                        result["title"] = title
                except Exception:
                    pass
    except Exception as e:
        print(f"[feed]   Failed to resolve {channel_username}/{msg_id}: {e}")

    return result


# ---------------------------------------------------------------------------
# HTML scraper for t.me/s/wiabsfeed
# ---------------------------------------------------------------------------

FEED_URL = "https://t.me/s/wiabsfeed"


def parse_duration(text: str) -> int:
    """Parse "M:SS" or "H:MM:SS" to seconds."""
    text = text.strip()
    parts = text.split(":")
    if len(parts) == 2:
        return int(parts[0]) * 60 + int(parts[1])
    if len(parts) == 3:
        return int(parts[0]) * 3600 + int(parts[1]) * 60 + int(parts[2])
    return 0


def parse_views(text: str) -> int:
    """Parse view count like '1', '1.2K', '3.5M'."""
    text = text.strip().upper()
    if not text:
        return 0
    multipliers = {"K": 1_000, "M": 1_000_000}
    for suffix, mult in multipliers.items():
        if text.endswith(suffix):
            return int(float(text[:-1]) * mult)
    try:
        return int(text)
    except ValueError:
        return 0


def scrape_feed() -> list[dict]:
    """Scrape t.me/s/wiabsfeed, resolve originals, extract enriched data."""
    print(f"[feed] Fetching {FEED_URL}")
    resp = requests.get(FEED_URL, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    items = []

    for msg in soup.select(".tgme_widget_message[data-post]"):
        # Skip service messages (channel created, etc.)
        if "service_message" in msg.get("class", []):
            continue

        video = msg.select_one("video[src]")
        if not video:
            continue

        cdn_url = video.get("src", "")
        if not cdn_url:
            continue

        # Post ID in @wiabsfeed
        data_post = msg.get("data-post", "")
        post_parts = data_post.split("/")
        message_id = int(post_parts[1]) if len(post_parts) == 2 else 0

        # Default author from @wiabsfeed (fallback)
        author_el = msg.select_one(".tgme_widget_message_from_author")
        author = author_el.get_text(strip=True) if author_el else ""

        # Duration from HTML
        duration_el = msg.select_one(".message_video_duration")
        duration = parse_duration(duration_el.get_text()) if duration_el else 0

        # Caption (protobuf)
        caption_el = msg.select_one(".js-message_text")
        caption = caption_el.get_text(strip=True) if caption_el else ""

        # Decode FeedPreview protobuf → get channelUsername, originalMsgId, title
        title = ""
        preview = decode_feed_preview(caption)
        if preview:
            # Title from FeedPreview (field 7)
            title = preview.get("title", "")
            # Duration from protobuf if available
            if preview.get("duration"):
                duration = preview["duration"]

            # Resolve original post for real author name
            channel_username = preview.get("channelUsername", "")
            original_msg_id = preview.get("originalMsgId", 0)
            if channel_username and original_msg_id:
                original = resolve_original_post(channel_username, original_msg_id)
                if original["author"]:
                    author = original["author"]
                # If FeedPreview had no title, try EncryptedVideo title
                if not title and original["title"]:
                    title = original["title"]
        else:
            title = caption

        # Views
        views_el = msg.select_one(".tgme_widget_message_views")
        views = parse_views(views_el.get_text()) if views_el else 0

        # Date
        time_el = msg.select_one("time[datetime]")
        date = time_el.get("datetime", "") if time_el else ""

        items.append({
            "cdn_url": cdn_url,
            "author": author,
            "duration": duration,
            "title": title,
            "message_id": message_id,
            "views": views,
            "date": date,
        })

    print(f"[feed] Found {len(items)} videos")
    return items


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    key_hex = os.environ.get("FEED_ENCRYPTION_KEY")
    if not key_hex:
        print("[feed] ERROR: FEED_ENCRYPTION_KEY env var not set", file=sys.stderr)
        sys.exit(1)

    items = scrape_feed()
    if not items:
        print("[feed] WARNING: No videos found, skipping update")
        sys.exit(0)

    for item in items:
        print(f"  #{item['message_id']} by {item['author']} "
              f"- \"{item['title']}\" ({item['duration']}s, {item['views']} views)")

    updated_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    protobuf = encode_guest_feed(items, updated_at)
    print(f"[feed] Protobuf size: {len(protobuf)} bytes")

    encrypted = encrypt_feed(protobuf, key_hex)
    print(f"[feed] Encrypted size: {len(encrypted)} bytes")

    out_path = Path(__file__).parent.parent / "feed.bin"
    out_path.write_bytes(encrypted)
    print(f"[feed] Written to {out_path}")


if __name__ == "__main__":
    main()
