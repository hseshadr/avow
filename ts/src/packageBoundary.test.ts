import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, join } from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = fileURLToPath(new URL("..", import.meta.url));
const ENTRY_PATH = join(PACKAGE_ROOT, "src", "index.ts");

const PUBLIC_MODULES = [
  "./canonical.js",
  "./errors.js",
  "./keys.js",
  "./receipt.js",
];

const PUBLIC_EXPORTS = [
  "AvowError",
  "CanonicalizationFailed",
  "JsonValue",
  "PayloadHashMismatch",
  "RECEIPT_SCHEMA",
  "ReceiptSchemaMismatch",
  "SignatureBytesInvalid",
  "SignatureInvalid",
  "SignedReceipt",
  "SignerMismatch",
  "canonicalBytes",
  "contentHash",
  "generateSeedHex",
  "publicKeyHex",
  "signPayload",
  "verifySignature",
];

const FORBIDDEN_TERMS = [
  "metrics",
  "ranking",
  "composite",
  "scoringErrors",
  "ReplayMismatch",
];

const PACKED_FILES = [
  "package/LICENSE",
  "package/README.md",
  "package/dist/canonical.d.ts",
  "package/dist/canonical.d.ts.map",
  "package/dist/canonical.js",
  "package/dist/canonical.js.map",
  "package/dist/errors.d.ts",
  "package/dist/errors.d.ts.map",
  "package/dist/errors.js",
  "package/dist/errors.js.map",
  "package/dist/index.d.ts",
  "package/dist/index.d.ts.map",
  "package/dist/index.js",
  "package/dist/index.js.map",
  "package/dist/keys.d.ts",
  "package/dist/keys.d.ts.map",
  "package/dist/keys.js",
  "package/dist/keys.js.map",
  "package/dist/receipt.d.ts",
  "package/dist/receipt.d.ts.map",
  "package/dist/receipt.js",
  "package/dist/receipt.js.map",
  "package/package.json",
];

interface EntryExports {
  modules: string[];
  names: string[];
}

interface PackOutput {
  filename: string;
}

function parseEntryExports(source: string): EntryExports {
  const file = ts.createSourceFile(
    ENTRY_PATH,
    source,
    ts.ScriptTarget.ESNext,
    true,
    ts.ScriptKind.TS,
  );
  const modules: string[] = [];
  const names: string[] = [];
  for (const statement of file.statements) {
    if (!ts.isExportDeclaration(statement)) continue;
    if (
      statement.moduleSpecifier &&
      ts.isStringLiteral(statement.moduleSpecifier)
    ) {
      modules.push(statement.moduleSpecifier.text);
    }
    if (statement.exportClause && ts.isNamedExports(statement.exportClause)) {
      names.push(
        ...statement.exportClause.elements.map((item) => item.name.text),
      );
    }
  }
  return { modules, names };
}

function packedFiles(): string[] {
  const destination = mkdtempSync(join(tmpdir(), "avow-pack-"));
  try {
    runPackageManager(["build"]);
    const output = runPackageManager([
      "pack",
      "--pack-destination",
      destination,
      "--json",
    ]);
    const parsed = JSON.parse(output) as PackOutput | PackOutput[];
    const packed = Array.isArray(parsed) ? parsed[0] : parsed;
    if (!packed) throw new Error("pnpm pack returned no archive metadata");
    const { filename } = packed;
    const archive = join(destination, basename(filename));
    return execFileSync("tar", ["-tf", archive], { encoding: "utf8" })
      .trim()
      .split("\n")
      .sort();
  } finally {
    rmSync(destination, { recursive: true, force: true });
  }
}

function verifierDeclarationDoc(): string {
  runPackageManager(["build"]);
  const declaration = readFileSync(
    join(PACKAGE_ROOT, "dist", "receipt.d.ts"),
    "utf8",
  );
  const signature = declaration.indexOf(
    "export declare function verifySignature",
  );
  const comment = declaration.lastIndexOf("/**", signature);
  return declaration.slice(comment, signature);
}

function runPackageManager(args: string[]): string {
  const executable = process.env.npm_execpath;
  if (executable) {
    return execFileSync(process.execPath, [executable, ...args], {
      cwd: PACKAGE_ROOT,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
    });
  }
  return execFileSync("pnpm", args, {
    cwd: PACKAGE_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
}

describe("standalone Avow package boundary", () => {
  it("documents verifier failures in their execution order", () => {
    const apiDoc = verifierDeclarationDoc();

    expect(apiDoc).toContain("ReceiptSchemaMismatch");
    expect(apiDoc.indexOf("ReceiptSchemaMismatch")).toBeLessThan(
      apiDoc.indexOf("PayloadHashMismatch"),
    );
  });

  it("exports only the canonical, receipt, key, and error kernel", () => {
    expect(
      existsSync(ENTRY_PATH),
      "src/index.ts must be the public entry",
    ).toBe(true);
    const source = existsSync(ENTRY_PATH)
      ? readFileSync(ENTRY_PATH, "utf8")
      : "";
    const publicEntry = parseEntryExports(source);
    expect(publicEntry.modules.sort()).toEqual(PUBLIC_MODULES);
    expect(publicEntry.names.sort()).toEqual(PUBLIC_EXPORTS.sort());
    for (const forbidden of FORBIDDEN_TERMS) {
      expect(source).not.toContain(forbidden);
    }
  });

  it("packs only metadata, documentation, license, and the built kernel", () => {
    expect(packedFiles()).toEqual(PACKED_FILES);
  });
});
