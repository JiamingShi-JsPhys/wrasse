from fastapi import Request


async def query_api(request: Request):
    data = await request.json()
    return await service.execute(data["sql"])
