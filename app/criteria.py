"""
Rule evaluation engine.

Each rule in the DB has these fields:
  added_months      — item must have been in library for at least N months
  unwatched_months  — no qualifying watch in last N months; NULL = never watched at all
  max_rating        — skip (protect) if rating >= this value
  min_rating        — skip (protect) if rating < this value
  max_plays         — only target if total qualifying plays < N
  min_size_gb       — only target if size >= N GB
  exclude_genres    — JSON array of genres; skip if item has any of these
  include_genres    — JSON array of genres; skip if item has NONE of these
"""

import json
import logging
from datetime import date, timedelta

log = logging.getLogger(__name__)

GB = 1_073_741_824


def evaluate(item: dict, rules: list[dict]) -> list[str]:
    """
    Returns a list of rule names that the item matches.
    An empty list means the item is safe.
    """
    matched = []
    for rule in rules:
        if not rule.get("enabled"):
            continue
        if rule.get("media_type", "both") != "both" and rule["media_type"] != item["media_type"]:
            continue
        if _matches(item, rule):
            matched.append(rule["name"])
    return matched


def _matches(item: dict, rule: dict) -> bool:
    today = date.today()

    # --- added_months: item must have been in library for at least N months ---
    if rule.get("added_months"):
        if not item.get("added_date"):
            return False  # unknown add date — don't delete
        added = date.fromisoformat(item["added_date"])
        cutoff = today - timedelta(days=rule["added_months"] * 30)
        if added > cutoff:
            return False  # added too recently

    # --- rating filters ---
    rating = item.get("imdb_rating")

    if rule.get("max_rating") is not None:
        # Protect items with rating >= max_rating (high quality)
        if rating is not None and rating >= rule["max_rating"]:
            return False

    if rule.get("min_rating") is not None:
        # Protect items with rating < min_rating (unrated / unknown)
        if rating is None or rating < rule["min_rating"]:
            return False

    # --- watch status ---
    if rule.get("unwatched_months") is None:
        # Rule targets items that have NEVER been watched to threshold
        if item.get("total_plays", 0) > 0:
            return False  # has been watched — safe
    else:
        # Rule targets items not watched within the last N months
        cutoff = today - timedelta(days=rule["unwatched_months"] * 30)
        last_watched = item.get("last_watched_date")
        if last_watched:
            try:
                lw_date = date.fromisoformat(last_watched)
                if lw_date >= cutoff:
                    return False  # watched recently enough — safe
            except Exception:
                pass
        # If last_watched is None, it's never been watched — qualifies

    # --- max_plays: only target if total plays below threshold ---
    if rule.get("max_plays") is not None:
        if item.get("total_plays", 0) >= rule["max_plays"]:
            return False

    # --- min_size_gb: only target items above this size ---
    if rule.get("min_size_gb") is not None:
        size_gb = (item.get("size_bytes") or 0) / GB
        if size_gb < rule["min_size_gb"]:
            return False

    # --- genre filters ---
    item_genres = [g.lower() for g in (item.get("genres") or [])]

    if rule.get("exclude_genres"):
        try:
            excluded = json.loads(rule["exclude_genres"]) if isinstance(rule["exclude_genres"], str) else rule["exclude_genres"]
            if any(g.lower() in item_genres for g in excluded):
                return False
        except Exception:
            pass

    if rule.get("include_genres"):
        try:
            included = json.loads(rule["include_genres"]) if isinstance(rule["include_genres"], str) else rule["include_genres"]
            if not any(g.lower() in item_genres for g in included):
                return False  # item has none of the required genres
        except Exception:
            pass

    return True
