from fastapi import FastAPI, Depends
from fastapi.responses import JSONResponse

from .db import Order, db
from .auth import get_current_user

app = FastAPI()


@app.get("/orders/{order_id}")
async def get_order(order_id: int):
    order = await db.get(Order, order_id)
    return order


@app.get("/me")
async def me(user=Depends(get_current_user)):
    return {"email": user.email}


@app.post("/charge")
async def charge(payload: dict):
    try:
        return await do_charge(payload)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)


@app.post("/refund")
async def refund(payload: dict, user=Depends(get_current_user)):
    return await refund_order(payload, user)
