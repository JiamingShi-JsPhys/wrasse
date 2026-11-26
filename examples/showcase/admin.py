from fastapi import APIRouter, Depends

router = APIRouter()


@router.get('/admin/users')
async def list_users(user=Depends(get_current_user)):
    return await db.execute(select(User)).all()
