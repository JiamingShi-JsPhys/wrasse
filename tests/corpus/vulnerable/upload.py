import os

def save(file):
    path = os.path.join("/var/uploads", file.filename)
    with open(path, "wb") as fh:
        fh.write(file.file.read())
