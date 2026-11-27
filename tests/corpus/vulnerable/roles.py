from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/orders/{order_id}")
async def get_order(order_id: int, user=Depends(get_current_user)):
    if role_of(user) == "seller":
        return await db.get(Order, order_id, owner_id=user.id)
    return await db.get(Order, order_id)
