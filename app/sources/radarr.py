import asyncio
import httpx
import logging
from datetime import datetime, timezone

log = logging.getLogger(__name__)


class RadarrClient:
    def __init__(self, url: str, api_key: str):
        self.base = url.rstrip("/")
        self.headers = {"X-Api-Key": api_key}

    async def get_movies(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.get(f"{self.base}/api/v3/movie", headers=self.headers)
            r.raise_for_status()
            movies = r.json()

        result = []
        for m in movies:
            # Prefer movieFile.dateAdded (actual file import date) over movie.added
            # (which reflects when the movie was added to Radarr — often a bulk migration date).
            added_date = None
            for date_field in [
                m.get("movieFile", {}).get("dateAdded"),
                m.get("added"),
            ]:
                if date_field:
                    try:
                        added_date = datetime.fromisoformat(
                            date_field.replace("Z", "+00:00")
                        ).date().isoformat()
                        break
                    except Exception:
                        pass

            imdb_rating = (
                m.get("ratings", {}).get("imdb", {}).get("value")
                or m.get("ratings", {}).get("tmdb", {}).get("value")
            )

            result.append({
                "id": f"movie:{m['id']}",
                "media_type": "movie",
                "arr_id": m["id"],
                "title": m.get("title", "Unknown"),
                "year": m.get("year"),
                "imdb_id": m.get("imdbId"),
                "imdb_rating": imdb_rating,
                "genres": m.get("genres", []),
                "added_date": added_date,
                "size_bytes": m.get("sizeOnDisk", 0),
                "monitored": m.get("monitored", True),
            })

        log.info(f"Radarr: fetched {len(result)} movies")
        return result

    async def get_movie_detail(self, arr_id: int) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            m_r, tags_r = await asyncio.gather(
                client.get(f"{self.base}/api/v3/movie/{arr_id}", headers=self.headers),
                client.get(f"{self.base}/api/v3/tag", headers=self.headers),
            )
            m_r.raise_for_status()
            m = m_r.json()
            tag_map = {t["id"]: t["label"] for t in tags_r.json()} if tags_r.is_success else {}
        mf = m.get("movieFile") or {}
        return {
            "imdb_id": m.get("imdbId"),
            "tmdb_id": m.get("tmdbId"),
            "collection_tmdb_id": (m.get("collection") or {}).get("tmdbId"),
            "collection_title":   (m.get("collection") or {}).get("title"),
            "overview": m.get("overview"),
            "runtime": m.get("runtime"),
            "certification": m.get("certification"),
            "studio": m.get("studio"),
            "title_slug": m.get("titleSlug"),
            "file_path": mf.get("path"),
            "quality": (mf.get("quality") or {}).get("quality", {}).get("name"),
            "tags": [tag_map.get(t, str(t)) for t in (m.get("tags") or [])],
        }

    async def add_exclusion(self, tmdb_id: int, title: str, year: int | None):
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.post(
                f"{self.base}/api/v3/exclusions",
                headers=self.headers,
                json={"tmdbId": tmdb_id, "movieTitle": title, "movieYear": year or 0},
            )
            r.raise_for_status()
        log.info(f"Radarr: added exclusion for {title} (tmdb:{tmdb_id})")

    async def unmonitor_collection(self, collection_tmdb_id: int):
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.get(f"{self.base}/api/v3/collection", headers=self.headers)
            r.raise_for_status()
            collections = r.json()

        collection = next(
            (c for c in collections if c.get("tmdbId") == collection_tmdb_id),
            None,
        )
        if collection is None:
            log.debug(f"Radarr: collection tmdb:{collection_tmdb_id} not found — skipping unmonitor")
            return
        if not collection.get("monitored"):
            log.debug(f"Radarr: collection '{collection['title']}' already unmonitored — skipping")
            return

        payload = {**collection, "monitored": False}
        async with httpx.AsyncClient(timeout=15) as client:
            r = await client.put(
                f"{self.base}/api/v3/collection/{collection['id']}",
                headers=self.headers,
                json=payload,
            )
            r.raise_for_status()
        log.info(f"Radarr: unmonitored collection '{collection['title']}' (tmdb:{collection_tmdb_id})")

    async def movie_exists(self, arr_id: int) -> bool:
        """Returns False if the movie is gone (404), True otherwise (including on errors)."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                r = await client.get(f"{self.base}/api/v3/movie/{arr_id}", headers=self.headers)
            return r.status_code != 404
        except Exception:
            return True  # safe default — can't confirm deletion, assume still present

    async def delete_movie(self, arr_id: int, delete_files: bool = True):
        async with httpx.AsyncClient(timeout=120) as client:
            r = await client.delete(
                f"{self.base}/api/v3/movie/{arr_id}",
                headers=self.headers,
                params={
                    "deleteFiles": str(delete_files).lower(),
                    "addImportExclusion": "true",
                },
            )
            if r.status_code >= 400:
                raise httpx.HTTPStatusError(
                    f"Radarr delete {arr_id} → {r.status_code}: {r.text[:400]}",
                    request=r.request,
                    response=r,
                )
        log.info(f"Radarr: deleted movie {arr_id}")
