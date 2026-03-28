import httpx
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class PlexClient:
    def __init__(self, url: str, token: str):
        self.base = url.rstrip("/")
        self.headers = {"X-Plex-Token": token, "Accept": "application/json"}

    async def _get(self, path: str, **params) -> dict:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(
                f"{self.base}{path}",
                headers=self.headers,
                params=params,
            )
            r.raise_for_status()
            return r.json()

    async def get_library_sections(self) -> list[dict]:
        data = await self._get("/library/sections")
        return data.get("MediaContainer", {}).get("Directory", [])

    async def get_machine_identifier(self) -> str | None:
        """Fetch the server's machineIdentifier from GET /."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(self.base, headers=self.headers)
                r.raise_for_status()
                data = r.json()
            return data.get("MediaContainer", {}).get("machineIdentifier")
        except Exception as e:
            log.warning(f"Plex: failed to fetch machineIdentifier: {e}")
            return None

    async def build_plex_maps(self) -> tuple[dict, dict, dict]:
        """
        Returns (watch_fallback, added_at_map, rating_key_map).

        watch_fallback: keyed by (title.lower(), year).
            Value: {"last_watched": ISO date | None, "max_percent": float, "total_plays": int}
            Only contains items that have been watched.

        added_at_map: keyed by (title.lower(), year).
            Value: ISO date string of addedAt. Contains ALL items.

        rating_key_map: keyed by (title.lower(), year).
            Value: Plex ratingKey (int) — used to build deep links.
        """
        log.info("Plex: building watch fallback and added-at maps...")
        sections = await self.get_library_sections()

        watch_fallback: dict[tuple, dict] = {}
        added_at_map: dict[tuple, str] = {}
        rating_key_map: dict[tuple, int] = {}

        for section in sections:
            section_type = section.get("type")
            section_key = section.get("key")

            if section_type == "movie":
                await self._process_movies(watch_fallback, added_at_map, rating_key_map, section_key)
            elif section_type == "show":
                await self._process_shows(watch_fallback, added_at_map, rating_key_map, section_key)

        log.info(
            f"Plex: {len(watch_fallback)} watched entries, "
            f"{len(added_at_map)} added-at entries"
        )
        return watch_fallback, added_at_map, rating_key_map

    async def _process_movies(self, watch_fallback: dict, added_at_map: dict, rating_key_map: dict, section_key: str):
        try:
            data = await self._get(f"/library/sections/{section_key}/all", type=1, includeGuids=1)
        except Exception as e:
            log.warning(f"Plex: failed to fetch movie section {section_key}: {e}")
            return

        for item in data.get("MediaContainer", {}).get("Metadata", []):
            title = item.get("title", "").strip().lower()
            year = item.get("year")
            if not title:
                continue

            key = (title, year)

            if item.get("ratingKey"):
                rating_key_map[key] = int(item["ratingKey"])

            added_at = self._ts_to_date(item.get("addedAt"))
            if added_at:
                added_at_map[key] = added_at

            view_count = item.get("viewCount", 0) or 0
            view_offset = item.get("viewOffset", 0) or 0
            if view_count == 0 and view_offset > 0:
                continue
            if view_count == 0:
                continue

            last_watched = self._ts_to_date(item.get("lastViewedAt"))
            self._merge_watch(watch_fallback, key, last_watched, view_count)

    async def _process_shows(self, watch_fallback: dict, added_at_map: dict, rating_key_map: dict, section_key: str):
        """
        Query at show level (type=2). viewedLeafCount > 0 means at least one episode watched.
        addedAt on a show item is when the show was first added to Plex.
        Year here is the show premiere year — matches Sonarr's year field directly.
        """
        try:
            data = await self._get(f"/library/sections/{section_key}/all", type=2)
        except Exception as e:
            log.warning(f"Plex: failed to fetch show section {section_key}: {e}")
            return

        for item in data.get("MediaContainer", {}).get("Metadata", []):
            title = item.get("title", "").strip().lower()
            year = item.get("year")
            if not title:
                continue

            key = (title, year)

            if item.get("ratingKey"):
                rating_key_map[key] = int(item["ratingKey"])
                rating_key_map[(title, None)] = int(item["ratingKey"])

            added_at = self._ts_to_date(item.get("addedAt"))
            if added_at:
                added_at_map[key] = added_at
                added_at_map[(title, None)] = added_at

            viewed_leaf_count = item.get("viewedLeafCount", 0) or 0
            if viewed_leaf_count == 0:
                continue

            last_watched = self._ts_to_date(item.get("lastViewedAt"))
            self._merge_watch(watch_fallback, key, last_watched, viewed_leaf_count)
            self._merge_watch(watch_fallback, (title, None), last_watched, viewed_leaf_count)

    @staticmethod
    def _ts_to_date(ts) -> str | None:
        if not ts:
            return None
        try:
            return datetime.fromtimestamp(int(ts), tz=timezone.utc).date().isoformat()
        except Exception:
            return None

    @staticmethod
    def _merge_watch(watch_fallback: dict, key: tuple, last_watched: str | None, plays: int):
        existing = watch_fallback.get(key)
        if existing is None:
            watch_fallback[key] = {
                "last_watched": last_watched,
                "max_percent": 90.0,
                "total_plays": plays,
            }
        else:
            existing["total_plays"] = max(existing["total_plays"], plays)
            if last_watched and (existing["last_watched"] is None or last_watched > existing["last_watched"]):
                existing["last_watched"] = last_watched
