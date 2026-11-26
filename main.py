import asyncio
import logging
import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
from core.database import init_db
from core.ioc_feeds import init_default_feeds
from core.tasks import mark_stale_endpoints_offline, maybe_update_ioc_feeds
from web.auth import ensure_setup_state
from web.api import register_routes
from config import APP_HOST, APP_PORT

log = logging.getLogger("aegisedr")


async def _offline_loop():
    while True:
        try:
            await mark_stale_endpoints_offline()
        except Exception:
            log.exception("offline sweep failed")
        await asyncio.sleep(30)


async def _ioc_loop():
    # Let the process finish startup before the first feed pull.
    await asyncio.sleep(15)
    while True:
        try:
            await maybe_update_ioc_feeds()
        except Exception:
            log.exception("IoC refresh failed")
        await asyncio.sleep(60)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await ensure_setup_state()
    await init_default_feeds()
    offline = asyncio.create_task(_offline_loop())
    ioc = asyncio.create_task(_ioc_loop())
    try:
        yield
    finally:
        offline.cancel()
        ioc.cancel()


app = FastAPI(title="AegisEDR", lifespan=lifespan)

_raw_origins = os.environ.get("AEGISEDR_ORIGINS", "")
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in _raw_origins.split(",")
    if origin.strip() and origin.strip().lower() != "null"
]
if ALLOWED_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Agent-Token"],
    )

register_routes(app)

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
    uvicorn.run("main:app", host=APP_HOST, port=APP_PORT, reload=False)
