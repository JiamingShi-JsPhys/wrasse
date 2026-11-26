from pydantic import BaseModel

class UserOut(BaseModel):
    email: str
    password: str
