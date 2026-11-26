async def execute(sql):
    return await db.execute(text(sql))
