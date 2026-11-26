import motor.motor_asyncio as motor


async def find_orders(db, request):
    query = request.json
    return await db.orders.find(query).to_list(None)
