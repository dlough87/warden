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
        Returns (watch_map, added_at_map, rating_key_map).

        All three maps are keyed by IMDB ID (str) when available, with title+year
        tuple aliases pointing to the same dict objects. Items without IMDB IDs fall
        back to title+year keys only. Shows are additionally keyed by (title, None)
        for year-mismatch fallback.

        watch_map values: {"last_watched": ISO date | None, "total_plays": int}
        added_at_map values: ISO date string
        rating_key_map values: Plex ratingKey (int)
        """
        log.info("Plex: building watch and added-at maps...")
        sections = await self.get_library_sections()

        watch_map: dict = {}
        added_at_map: dict = {}
        rating_key_map: dict = {}
        rating_key_to_imdb: dict[str, str] = {}   # plex ratingKey → imdb_id bridge
        rating_key_to_year: dict[str, int | None] = {}  # plex ratingKey → release year
        rating_key_to_title: dict[str, str] = {}  # plex ratingKey → lowercase title
        show_titles: set[str] = set()             # lowercase titles of all current library shows

        for section in sections:
            section_type = section.get("type")
            section_key = section.get("key")

            if section_type == "movie":
                await self._process_movies(
                    watch_map, added_at_map, rating_key_map,
                    rating_key_to_imdb, rating_key_to_year, rating_key_to_title, section_key
                )
            elif section_type == "show":
                await self._process_shows(
                    watch_map, added_at_map, rating_key_map,
                    rating_key_to_imdb, rating_key_to_year, rating_key_to_title,
                    show_titles, section_key
                )

        log.info(
            f"Plex: {len(watch_map)} watch entries from library metadata, "
            f"{len(added_at_map)} added-at entries"
        )

        await self._supplement_from_history(
            watch_map, rating_key_to_imdb, rating_key_to_year,
            rating_key_to_title, show_titles,
        )

        return watch_map, added_at_map, rating_key_map

    async def _process_movies(
        self,
        watch_map: dict,
        added_at_map: dict,
        rating_key_map: dict,
        rating_key_to_imdb: dict,
        rating_key_to_year: dict,
        rating_key_to_title: dict,
        section_key: str,
    ):
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

            imdb_id = self._extract_imdb_id(item)
            primary_key = imdb_id if imdb_id else (title, year)

            added_at = self._ts_to_date(item.get("addedAt"))

            if item.get("ratingKey"):
                rk = int(item["ratingKey"])
                rating_key_map[primary_key] = rk
                if imdb_id:
                    rating_key_map[(title, year)] = rk
                    rating_key_to_imdb[str(rk)] = imdb_id
                rating_key_to_year[str(rk)] = year
                rating_key_to_title[str(rk)] = title

            if added_at:
                added_at_map[primary_key] = added_at
                if imdb_id:
                    added_at_map[(title, year)] = added_at

            view_count = item.get("viewCount", 0) or 0
            last_watched = self._ts_to_date(item.get("lastViewedAt"))

            if view_count == 0 and not last_watched:
                continue

            self._merge_watch(watch_map, primary_key, last_watched, view_count)
            if imdb_id:
                watch_map[(title, year)] = watch_map[imdb_id]

    async def _process_shows(
        self,
        watch_map: dict,
        added_at_map: dict,
        rating_key_map: dict,
        rating_key_to_imdb: dict,
        rating_key_to_year: dict,
        rating_key_to_title: dict,
        show_titles: set,
        section_key: str,
    ):
        """
        Query at show level (type=2). viewedLeafCount > 0 means at least one episode watched.
        addedAt on a show item is when the show was first added to Plex.
        Year here is the show premiere year — matches Sonarr's year field directly.
        """
        try:
            data = await self._get(f"/library/sections/{section_key}/all", type=2, includeGuids=1)
        except Exception as e:
            log.warning(f"Plex: failed to fetch show section {section_key}: {e}")
            return

        for item in data.get("MediaContainer", {}).get("Metadata", []):
            title = item.get("title", "").strip().lower()
            year = item.get("year")
            if not title:
                continue

            show_titles.add(title)

            imdb_id = self._extract_imdb_id(item)
            primary_key = imdb_id if imdb_id else (title, year)

            added_at = self._ts_to_date(item.get("addedAt"))

            if item.get("ratingKey"):
                rk = int(item["ratingKey"])
                rating_key_map[primary_key] = rk
                rating_key_map[(title, None)] = rk
                if imdb_id:
                    rating_key_map[(title, year)] = rk
                    rating_key_to_imdb[str(rk)] = imdb_id
                rating_key_to_year[str(rk)] = year
                rating_key_to_title[str(rk)] = title

            if added_at:
                added_at_map[primary_key] = added_at
                added_at_map[(title, None)] = added_at
                if imdb_id:
                    added_at_map[(title, year)] = added_at

            viewed_leaf_count = item.get("viewedLeafCount", 0) or 0
            last_watched = self._ts_to_date(item.get("lastViewedAt"))

            if viewed_leaf_count == 0 and not last_watched:
                continue

            self._merge_watch(watch_map, primary_key, last_watched, viewed_leaf_count)
            watch_map[(title, None)] = watch_map[primary_key]
            if imdb_id:
                watch_map[(title, year)] = watch_map[imdb_id]

    async def _supplement_from_history(
        self,
        watch_map: dict,
        rating_key_to_imdb: dict,
        rating_key_to_year: dict,
        rating_key_to_title: dict,
        show_titles: set,
    ) -> None:
        """
        Supplement watch_map with play counts and last_watched from Plex's history.

        Needed when library metadata (viewedLeafCount/lastViewedAt) is absent — e.g.
        after a Plex server migration. History plays are attributed via the
        rating_key → imdb_id bridge built during the library scan, so title mismatches
        between Radarr/Sonarr and Plex don't affect attribution.
        """
        log.info("Plex: fetching play history...")
        try:
            async with httpx.AsyncClient(timeout=120) as client:
                r = await client.get(
                    f"{self.base}/status/sessions/history/all",
                    headers=self.headers,
                    params={"sort": "viewedAt:desc", "X-Plex-Container-Size": 100000, "includeGuids": 1},
                )
                r.raise_for_status()
                data = r.json()
        except Exception as e:
            log.warning(f"Plex: play history unavailable: {e}")
            return

        records = data.get("MediaContainer", {}).get("Metadata") or []
        log.info(f"Plex: {len(records)} history records fetched")

        history: dict = {}
        for entry in records:
            media_type = entry.get("type", "")
            viewed_date = self._ts_to_date(entry.get("viewedAt"))
            if not viewed_date:
                continue

            if media_type == "episode":
                rk_str = str(entry.get("grandparentRatingKey") or "")
                title = (entry.get("grandparentTitle") or "").strip().lower()
                year = entry.get("grandparentYear") or entry.get("parentYear")
                direct_imdb = None
            elif media_type == "movie":
                rk_str = str(entry.get("ratingKey") or "")
                title = (entry.get("title") or "").strip().lower()
                year = entry.get("year")
                direct_imdb = self._extract_imdb_id(entry)
            else:
                continue

            # Two-path attribution:
            #
            # Path A — ratingKey resolves to a current library item via IMDB bridge:
            #   Use IMDB ID as primary key. Apply a year guard: if viewedAt predates the
            #   current item's release year the ratingKey was reused after the original
            #   item was deleted (e.g. a 2015 play attributed to a 2022 show). Discard
            #   those records entirely — do NOT fall through to title matching, because
            #   the title in the record belongs to the old deleted item.
            #
            # Path B — ratingKey unknown (item deleted or re-indexed with a new key):
            #   Fall back to title+year matching. This correctly handles shows whose Plex
            #   ratingKey changed (e.g. after a library re-scan or server migration) while
            #   their play history still references the old key.
            imdb_id = direct_imdb or rating_key_to_imdb.get(rk_str)
            if imdb_id:
                # Title guard: if attribution came from the ratingKey bridge (not a direct
                # IMDB match in the history record itself), verify the record's title matches
                # the current library item. A mismatch means the ratingKey was recycled after
                # the original item was deleted — discard rather than crediting the wrong item.
                if not direct_imdb:
                    bridge_title = rating_key_to_title.get(rk_str)
                    if bridge_title and title and title != bridge_title:
                        continue  # ratingKey reused by a different item — discard
                # Guard A — release year: play can't predate the item's premiere
                item_year = rating_key_to_year.get(rk_str)
                if item_year and viewed_date < f"{item_year}-01-01":
                    continue  # ratingKey reused — stale record, discard
            else:
                # Orphan path: ratingKey unknown (item deleted or re-indexed)
                # For movies: require year — title alone is ambiguous across films.
                # For episodes without year: Plex often omits grandparentYear and
                # grandparentRatingKey for other-user plays. Allow (title, None) matching
                # ONLY if that key already exists in watch_map — i.e. the show is currently
                # in the library. This prevents orphan records for deleted shows from
                # polluting entries for unrelated items with the same title.
                if not year:
                    if media_type == "movie":
                        continue
                    if not title or title not in show_titles:
                        continue

            if not title and not imdb_id:
                continue

            # Build keys: IMDB ID primary, title+year fallback.
            # (title, None) alias only written when IMDB-resolved to prevent
            # cross-show title collisions.
            keys: list = []
            if imdb_id:
                keys.append(imdb_id)
            if title:
                keys.append((title, year))
                if media_type == "episode" and imdb_id:
                    keys.append((title, None))

            # Find or create the shared dict for this item across all its keys
            h = None
            for key in keys:
                h = history.get(key)
                if h is not None:
                    break

            if h is None:
                h = {"last_watched": viewed_date, "total_plays": 0}

            h["total_plays"] += 1
            if viewed_date > h.get("last_watched", ""):
                h["last_watched"] = viewed_date

            for key in keys:
                history[key] = h

        # Merge history into watch_map — max() ensures no double-counting when both
        # library metadata and history are present for the same item
        for key, h in history.items():
            existing = watch_map.get(key)
            if existing is None:
                watch_map[key] = h
            else:
                existing["total_plays"] = max(existing["total_plays"], h["total_plays"])
                if not existing.get("last_watched") or h["last_watched"] > existing["last_watched"]:
                    existing["last_watched"] = h["last_watched"]

        log.info(f"Plex: {len(watch_map)} total entries after history supplement")

    @staticmethod
    def _extract_imdb_id(item: dict) -> str | None:
        """Extract IMDB ID from Plex's Guid array, e.g. 'tt1234567'."""
        for guid in item.get("Guid") or []:
            gid = guid.get("id", "")
            if gid.startswith("imdb://"):
                return gid[7:]
        return None

    @staticmethod
    def _ts_to_date(ts) -> str | None:
        if not ts:
            return None
        try:
            return datetime.fromtimestamp(int(ts), tz=timezone.utc).date().isoformat()
        except Exception:
            return None

    @staticmethod
    def _merge_watch(watch_map: dict, key, last_watched: str | None, plays: int):
        existing = watch_map.get(key)
        if existing is None:
            watch_map[key] = {"last_watched": last_watched, "total_plays": plays}
        else:
            existing["total_plays"] = max(existing["total_plays"], plays)
            if last_watched and (existing["last_watched"] is None or last_watched > existing["last_watched"]):
                existing["last_watched"] = last_watched
