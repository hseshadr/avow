import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
    coverage: {
      provider: "v8",
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.test.ts", "src/index.ts"],
      // Kernel logic floor — the canonicalize + verify + pinned-key + tamper paths.
      thresholds: {
        lines: 90,
        functions: 90,
        branches: 90,
      },
    },
  },
});
