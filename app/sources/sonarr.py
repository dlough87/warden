import httpx
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class SonarrClient:
    def __init__(self, url: str, api_key: str):
        self.base = url.rstrip("/")
        self.headers = {"X-Api-Key": api_key}

    async def get_series(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{self.base}/api/v3/series", headers=self.headers)
            r.raise_for_status()
            series_list = r.json()

        result = []
        for s in series_list:
            added_date = None
            if s.get("added"):
                try:
                    added_date = datetime.fromisoformat(
                        s["added"].replace("Z", "+00:00")
                    ).date().isoformat()
                except Exception:
                    pass

            # Sonarr exposes a TVDB community rating, not a pure IMDB score
            rating = s.get("ratings", {}).get("value")

            # Size: sum across all season statistics
            size_bytes = s.get("statistics", {}).get("sizeOnDisk", 0)

            result.append({
                "id": f"show:{s['id']}",
                "media_type": "show",
                "arr_id": s["id"],
                "title": s.get("title", "Unknown"),
                "year": s.get("year"),
                "tvdb_id": s.get("tvdbId"),
                "imdb_id": s.get("imdbId"),
                "imdb_rating": rating,  # TVDB proxy — noted in UI
                "genres": s.get("genres", []),
                "added_date": added_date,
                "size_bytes": size_bytes,
                "monitored": s.get("monitored", True),
            })

        log.info(f"Sonarr: fetched {len(result)} series")
        return result

    async def get_series_detail(self, arr_id: int) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{self.base}/api/v3/series/{arr_id}", headers=self.headers)
            r.raise_for_status()
            s = r.json()
        stats = s.get("statistics") or {}
        return {
            "imdb_id": s.get("imdbId"),
            "tvdb_id": s.get("tvdbId"),
            "overview": s.get("overview"),
            "network": s.get("network"),
            "status": s.get("status"),
            "runtime": s.get("runtime"),
            "title_slug": s.get("titleSlug"),
            "file_path": s.get("path"),
            "season_count": stats.get("seasonCount"),
            "episode_count": stats.get("episodeCount"),
            "episode_file_count": stats.get("episodeFileCount"),
        }

    async def add_exclusion(self, tvdb_id: int, title: str):
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{self.base}/api/v3/importlistexclusion",
                headers=self.headers,
                json={"tvdbId": tvdb_id, "title": title},
            )
            r.raise_for_status()
        log.info(f"Sonarr: added exclusion for {title} (tvdb:{tvdb_id})")

    async def delete_series(self, arr_id: int, delete_files: bool = True):
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.delete(
                f"{self.base}/api/v3/series/{arr_id}",
                headers=self.headers,
                params={"deleteFiles": str(delete_files).lower()},
            )
            r.raise_for_status()
        log.info(f"Sonarr: deleted series {arr_id}")
