def handler(request, cursor):
    name = request.query_params["name"]
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
