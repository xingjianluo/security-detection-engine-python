import contextlib
import logging

from fastapi import FastAPI

from detection.api import router as detection_router
from detection.service import DetectionService

# Configure console logging only if the process has not already configured
# handlers (e.g. pytest attaches its own live-log handler).
if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.detection_service = DetectionService()
    try:
        yield
    finally:
        app.state.detection_service.close()


app = FastAPI(lifespan=lifespan)
app.include_router(detection_router)


@app.get("/")
def read_root():
    # Original endpoint, unchanged.
    return {"Hello": "World"}
