"use strict";

const fs = require("fs");
const path = require("path");

const CJS_DIR = path.resolve(__dirname, "..", "dist", "cjs");

if (!fs.existsSync(CJS_DIR)) {
  console.error(`CJS output directory not found: ${CJS_DIR}`);
  process.exit(1);
}

/**
 * Collect every file under dist/cjs, then rename .js -> .cjs and
 * .js.map -> .cjs.map so the require() paths declared in package.json
 * ("require": "./dist/cjs/*.cjs") actually resolve.
 */
const files = [];
function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
    } else {
      files.push(full);
    }
  }
}
walk(CJS_DIR);

const renamed = new Map(); // old path -> new path

for (const file of files) {
  const ext = path.extname(file);
  if (ext === ".js") {
    const newPath = file.slice(0, -3) + ".cjs";
    fs.renameSync(file, newPath);
    renamed.set(file, newPath);
  } else if (ext === ".map" && file.endsWith(".js.map")) {
    const newPath = file.slice(0, -4) + ".cjs.map";
    fs.renameSync(file, newPath);
    renamed.set(file, newPath);
  }
}

/**
 * Rewrite internal relative require() paths from `.js` to `.cjs`.
 * Only relative imports ("./" or "../") are rewritten; bare package
 * imports ("jose") and Node builtins ("node:crypto") are left alone.
 */
const requireRe = /require\((["'])(\.\.?\/[^"']*?)\.js\1\)/g;

for (const [, newPath] of renamed) {
  if (!newPath.endsWith(".cjs")) continue;
  let content = fs.readFileSync(newPath, "utf8");
  const next = content.replace(requireRe, (match, quote, relPath) => {
    return `require(${quote}${relPath}.cjs${quote})`;
  });
  if (next !== content) {
    fs.writeFileSync(newPath, next, "utf8");
  }
}

console.log(
  `fix-cjs-imports: renamed ${renamed.size} file(s) and rewrote internal require paths in dist/cjs`,
);
