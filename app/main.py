from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.ot_ingestion import router as ot_ingestion_router
from app.db.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="AlertStack OT",
    description="OT/ICS security monitoring and detection platform",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(ot_ingestion_router)


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "alertstack-ot",
    }
