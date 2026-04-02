from fastapi import FastAPI
from .database import Base, engine
from .auth import router as auth_router

app = FastAPI(title="Creator Chatbot MVP")

# Include auth endpoints
app.include_router(auth_router)

@app.on_event("startup")
async def startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.get("/")
def root():
    return {"message": "MVP Chatbot is live!"}
