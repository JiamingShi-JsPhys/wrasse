# wrasse (npm launcher)

wrasse is a Python CLI. This package installs a `wrasse` command that finds your
installed copy of the Python tool and runs it with the same arguments.

```
pip install --pre wrasse
npx wrasse-audit audit . --offline
```

There is no scanner in this package. Without the Python package the launcher
prints the pip command and exits with 127.

The tool itself, its rules and the docs live at
https://github.com/JiamingShi-JsPhys/wrasse
