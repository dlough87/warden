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
            r = await client.get(f"{self.base}/api/v3/movie/{arr_id}", headers=self.headers)
            r.raise_for_status()
            m = r.json()
        mf = m.get("movieFile") or {}
        return {
            "imdb_id": m.get("imdbId"),
            "tmdb_id": m.get("tmdbId"),
            "overview": m.get("overview"),
            "runtime": m.get("runtime"),
            "certification": m.get("certification"),
            "studio": m.get("studio"),
            "title_slug": m.get("titleSlug"),
            "file_path": mf.get("path"),
            "quality": (mf.get("quality") or {}).get("quality", {}).get("name"),
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

    async def delete_movie(self, arr_id: int, delete_files: bool = True):
        async with httpx.AsyncClient(timeout=30) as client:
            r = await client.delete(
                f"{self.base}/api/v3/movie/{arr_id}",
                headers=self.headers,
                params={"deleteFiles": str(delete_files).lower()},
            )
            r.raise_for_status()
        log.info(f"Radarr: deleted movie {arr_id}")
