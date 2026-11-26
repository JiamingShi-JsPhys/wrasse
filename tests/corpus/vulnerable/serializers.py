from pydantic import BaseModel


class CustomerOut(BaseModel):
    email: str
    id_card: str
