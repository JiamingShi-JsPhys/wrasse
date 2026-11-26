"""Rule catalogue for the docs.

Banned calls: pickle.loads, marshal.loads, os.popen, subprocess.run.
"""

BANNED = ["pickle.loads", "marshal.loads"]
