from fastapi.responses import JSONResponse

def handler(e):
    return JSONResponse({"error": str(e)}, status_code=500)
