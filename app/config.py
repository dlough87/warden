"""
Configuration helpers.

All connection credentials are stored in the SQLite settings table.
Use `await get_config_async()` to obtain a fresh config object each call.
The synchronous `get_config()` shim raises an error — migrate callers to
the async version.

server.port is read from the WARDEN_PORT environment variable (default 8787).
"""

import os
from pydantic import BaseModel

from .database import get_connection_settings


class PlexConfig(BaseModel):
    url: str = ""
    token: str = ""
    public_url: str = ""


class TautulliConfig(BaseModel):
    url: str = ""
    api_key: str = ""
    public_url: str = ""


class RadarrConfig(BaseModel):
    url: str = ""
    api_key: str = ""
    public_url: str = ""


class SonarrConfig(BaseModel):
    url: str = ""
    api_key: str = ""
    public_url: str = ""


class DiscordConfig(BaseModel):
    webhook_url: str = ""


class NotificationsConfig(BaseModel):
    discord: DiscordConfig = DiscordConfig()


class ServerConfig(BaseModel):
    port: int = 8787


class AppConfig(BaseModel):
    plex: PlexConfig = PlexConfig()
    tautulli: TautulliConfig = TautulliConfig()
    radarr: RadarrConfig = RadarrConfig()
    sonarr: SonarrConfig = SonarrConfig()
    notifications: NotificationsConfig = NotificationsConfig()
    server: ServerConfig = ServerConfig()


async def get_config_async() -> AppConfig:
    """Return a fresh AppConfig built from the SQLite settings table."""
    s = await get_connection_settings()
    port = int(os.environ.get("WARDEN_PORT", 8787))
    return AppConfig(
        plex=PlexConfig(
            url=s.get("plex_url", ""),
            token=s.get("plex_token", ""),
            public_url=s.get("plex_public_url", ""),
        ),
        tautulli=TautulliConfig(
            url=s.get("tautulli_url", ""),
            api_key=s.get("tautulli_api_key", ""),
            public_url=s.get("tautulli_public_url", ""),
        ),
        radarr=RadarrConfig(
            url=s.get("radarr_url", ""),
            api_key=s.get("radarr_api_key", ""),
            public_url=s.get("radarr_public_url", ""),
        ),
        sonarr=SonarrConfig(
            url=s.get("sonarr_url", ""),
            api_key=s.get("sonarr_api_key", ""),
            public_url=s.get("sonarr_public_url", ""),
        ),
        notifications=NotificationsConfig(
            discord=DiscordConfig(
                webhook_url=s.get("discord_webhook_url", ""),
            ),
        ),
        server=ServerConfig(port=port),
    )


def get_config():
    raise RuntimeError(
        "get_config() is no longer supported. "
        "Use `await get_config_async()` instead."
    )
