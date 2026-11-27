#!/usr/bin/env node
// wrasse is a Python program. This package finds an installed copy and forwards
// its arguments; it contains no scanner of its own.
const { spawnSync } = require("node:child_process");

const passthrough = process.argv.slice(2);
const pythons = process.platform === "win32" ? ["python", "py", "python3"] : ["python3", "python"];
const missing =
  "wrasse: the Python package is not installed.\n\n" +
  "  pip install --pre wrasse\n\n" +
  "The npm package is only a launcher. Source and docs:\n" +
  "  https://github.com/JiamingShi-JsPhys/wrasse";

function run(cmd, args) {
  const result = spawnSync(cmd, args, { stdio: "inherit" });
  if (result.error && result.error.code === "ENOENT") return null;
  if (result.error) {
    console.error(`wrasse: ${result.error.message}`);
    process.exit(1);
  }
  return result.status === null ? 1 : result.status;
}

// 1. The module, through whichever interpreter already has it. Trying this first
//    keeps a `wrasse` executable from being found when that executable is us.
for (const python of pythons) {
  const probe = spawnSync(python, ["-c", "import wrasse"], { stdio: "ignore" });
  if (probe.error || probe.status !== 0) continue;
  const code = run(python, ["-m", "wrasse", ...passthrough]);
  process.exit(code === null ? 127 : code);
}

// 2. A `wrasse` script on PATH, which is what `pip install wrasse` creates.
const direct = run("wrasse", passthrough);
if (direct !== null) process.exit(direct);

console.error(missing);
process.exit(127);
