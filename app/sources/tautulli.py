import httpx
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Tautulli returns percent_complete as 0-100
# We match items to Radarr/Sonarr via title+year.
# For TV episodes the history record's `year` field is often the episode air year,
# NOT the show premiere year. We therefore store each episode under TWO keys:
#   (grandparent_title, year)   — whatever year Tautulli gives us
#   (grandparent_title, None)   — title-only fallback
# Lookup tries year-keyed first, then title-only fallback.


class TautulliClient:
    def __init__(self, url: str, api_key: str):
        self.base = url.rstrip("/")
        self.api_key = api_key

    async def _get(self, cmd: str, **params) -> dict:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.get(
                f"{self.base}/api/v2",
                params={"apikey": self.api_key, "cmd": cmd, **params},
            )
            r.raise_for_status()
            data = r.json()
            if data.get("response", {}).get("result") != "success":
                raise RuntimeError(f"Tautulli error: {data}")
            return data["response"]["data"]

    async def get_watch_map(self, threshold_percent: float) -> dict:
        """
        Returns a dict keyed by (title.lower(), year|None).
        Value: {"last_watched": ISO date str | None, "max_percent": float, "total_plays": int}
        Items with no session >= threshold are not in the map (treat as unwatched).

        Each TV episode is stored under BOTH (title, year) and (title, None) to
        handle year mismatches between Tautulli history and Sonarr premiere year.
        """
        log.info("Tautulli: fetching full watch history...")
        data = await self._get("get_history", length=100000, media_type="movie,episode")
        records = data.get("data", [])
        log.info(f"Tautulli: {len(records)} history records fetched")

        watch_map: dict[tuple, dict] = {}

        for rec in records:
            pct = float(rec.get("percent_complete", 0))
            if pct < threshold_percent:
                continue

            media_type = rec.get("media_type", "")
            if media_type == "episode":
                title = rec.get("grandparent_title", "").strip().lower()
                # grandparent_year is the show premiere year; year may be episode air year
                year = rec.get("grandparent_year") or rec.get("year")
            else:
                title = rec.get("title", "").strip().lower()
                year = rec.get("year")

            if not title:
                continue

            viewed_at = rec.get("date")  # Unix timestamp
            viewed_date = None
            if viewed_at:
                try:
                    viewed_date = datetime.fromtimestamp(int(viewed_at), tz=timezone.utc).date().isoformat()
                except Exception:
                    pass

            # Always update the year-keyed entry
            self._merge(watch_map, (title, year), pct, viewed_date)

            # For episodes, also maintain a title-only fallback key
            if media_type == "episode":
                self._merge(watch_map, (title, None), pct, viewed_date)

        log.info(f"Tautulli: {len(watch_map)} entries with qualifying watches (incl. title-only keys)")
        return watch_map

    @staticmethod
    def _merge(watch_map: dict, key: tuple, pct: float, viewed_date: str | None):
        existing = watch_map.get(key)
        if existing is None:
            watch_map[key] = {
                "last_watched": viewed_date,
                "max_percent": pct,
                "total_plays": 1,
            }
        else:
            existing["total_plays"] += 1
            existing["max_percent"] = max(existing["max_percent"], pct)
            if viewed_date and (existing["last_watched"] is None or viewed_date > existing["last_watched"]):
                existing["last_watched"] = viewed_date

    def lookup(self, watch_map: dict, title: str, year: int | None) -> dict | None:
        """Try year-keyed lookup first, fall back to title-only (for TV show year mismatches)."""
        key = (title.strip().lower(), year)
        result = watch_map.get(key)
        if result is None and year is not None:
            result = watch_map.get((title.strip().lower(), None))
        return result
