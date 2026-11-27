import hashlib

import requests
from pydantic import BaseModel


class UserUpdate(BaseModel):
    email: str
    is_admin: bool = False


def fetch_avatar(user_id: int):
    return requests.get(f"https://cdn.example.com/avatar/{user_id}")


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()
