from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    order = await db.get(Order, order_id)
    return order

@router.get("/me")
async def me(user=Depends(get_current_user)):
    return user
