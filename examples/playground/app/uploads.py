import os

from fastapi import APIRouter, UploadFile

router = APIRouter()
UPLOAD_DIR = "/var/app/uploads"


@router.post("/files")
async def upload(file: UploadFile):
    path = os.path.join(UPLOAD_DIR, file.filename)
    with open(path, "wb") as fh:
        fh.write(await file.read())
    return {"saved": file.filename}
