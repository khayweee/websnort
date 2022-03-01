import sys
from typing import List

from snort.snort import Snort
from runner import Runner
import config

from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse


def get_application():
    app = FastAPI(title=config.PROJECT_NAME,
                  version=config.VERSION)
    return app

app = get_application()

@app.get("/api/health", name="websnort:health")
async def health(request: Request):
    client_ip = request.client
    result = {
        "msg": "All Good",
        "status": True,
        "client_ip": client_ip[0],
        "client_port": client_ip[1]
    }
    return result

@app.get("/")
async def main():
    content = """
<body>
<form action="/files/" enctype="multipart/form-data" method="post">
<input name="files" type="file" multiple>
<input type="submit">
</form>
<form action="/uploadfiles/" enctype="multipart/form-data" method="post">
<input name="files" type="file" multiple>
<input type="submit">
</form>
</body>
    """
    return HTMLResponse(content=content)


@app.post("/files/")
async def create_files(
    files: List[bytes] = File(..., description="Multiple files as bytes")
):
    return {"file_sizes": [len(file) for file in files]}


@app.post("/uploadfiles/")
async def create_upload_files(
    files: List[UploadFile] = File(..., description="Multiple files as UploadFile")
):
    return {"filenames": [file.filename for file in files]}



if __name__ == "__main__":
    main()