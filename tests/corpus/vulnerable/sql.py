import subprocess, os
import requests

def handler(request, user_id):
    name = request.query_params["name"]
    db.execute(f"SELECT * FROM users WHERE name = '{name}'")
    os.system(f"id {name}")
    requests.get(request.query_params["url"])
    return open(os.path.join("/data", name))
