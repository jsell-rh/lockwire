import * as esbuild from "esbuild";
import { readFileSync, writeFileSync, mkdirSync } from "fs";

mkdirSync("dist", { recursive: true });

const result = await esbuild.build({
  entryPoints: ["src/main.ts"],
  bundle: true,
  minify: true,
  format: "iife",
  target: "es2022",
  write: false,
  sourcemap: false,
  legalComments: "none",
});

const js = result.outputFiles[0].text;
const template = readFileSync("src/template.html", "utf-8");
const html = template.replace("/* __BUNDLE__ */", js);
writeFileSync("dist/index.html", html);
console.log(`Built dist/index.html (${(html.length / 1024).toFixed(1)} KB)`);
