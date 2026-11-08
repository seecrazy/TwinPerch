#!/usr/bin/env node
/**
 * 打包管线（docs/04 §3 / README）：把 Worker/src 编译成单文件 ESM，
 * 以 Base64 内嵌进 Swift 生成文件，供 CloudflareDeployer 上传。
 * 这是唯一允许产生部署脚本的路径——与 Worker/src 同源，杜绝两份实现漂移。
 *
 * 用法：npm run bundle
 * 产物：TwinPerch/Sources/TwinPerchKit/Transport/RelayScript.generated.swift
 */
import { build } from "esbuild";
import { writeFileSync, mkdirSync } from "node:fs";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..");
const outSwiftDir = join(root, "TwinPerch", "Sources", "TwinPerchKit", "Transport");
const outSwift = join(outSwiftDir, "RelayScript.generated.swift");

const result = await build({
  entryPoints: [join(here, "src", "index.ts")],
  bundle: true,
  format: "esm",
  platform: "browser", // Workers 运行时接近浏览器全局（无 node 内置依赖）
  target: "es2022",
  minify: true,
  legalComments: "none",
  write: false,
  define: { "process.env.NODE_ENV": '"production"' },
});

const js = result.outputFiles[0].text;
if (!js.includes("Room")) {
  console.error("bundle 异常：产物中未找到 Room 类，拒绝写入");
  process.exit(1);
}

const b64 = Buffer.from(js, "utf8").toString("base64");
const swift = `// 由 Worker/build.mjs 自动生成——勿手改。运行 \`cd Worker && npm run bundle\` 更新。
// content 为 esbuild 打包产物（单文件 ESM）的 Base64；脚本版本以 Worker/package.json 为准。
enum RelayScriptGenerated {
    static let contentBase64: String? = "${b64}"
}
`;
mkdirSync(outSwiftDir, { recursive: true });
writeFileSync(outSwift, swift);

const rel = relative(process.cwd(), outSwift);
console.log(`bundle ok: ${js.length} bytes js -> ${rel}`);
