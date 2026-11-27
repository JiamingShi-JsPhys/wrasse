import html

from fastapi.responses import HTMLResponse


async def show(request):
    name = request.query_params["name"]
    return HTMLResponse(f"<h1>Hello {html.escape(name)}</h1>")
