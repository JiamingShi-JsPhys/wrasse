import urllib.request

ALLOWED = {"pypi.org"}

def fetch(url):
    if urllib.parse.urlparse(url).netloc not in ALLOWED:
        raise ValueError("refusing to fetch")
    return urllib.request.urlopen(url).read()
