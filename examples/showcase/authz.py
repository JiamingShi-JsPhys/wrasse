from fastapi import APIRouter, Depends
router = APIRouter()

@router.get("/orders/{order_id}")
async def get_order(order_id: int):
    return await db.get(Order, order_id)

@router.post("/refund")
async def refund(payload: dict, user=Depends(get_current_user)):
    return await do_refund(payload, user)
