import requests
from pydantic import BaseModel


class UserProfile(BaseModel):
    email: str
    is_admin: bool


def fetch_profile(user_id: int):
    return requests.get(f"https://api.example.com/users/{user_id}", timeout=10)
