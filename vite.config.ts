import { defineConfig } from "vite-plus";

export default defineConfig({
  staged: {
    "*": "vp check --fix",
  },
  lint: { options: { typeAware: true, typeCheck: true } },
  fmt: {
    trailingComma: "all",
    tabWidth: 2,
    semi: true,
    singleQuote: false,
    printWidth: 120,
    arrowParens: "always",
    bracketSpacing: true,
    bracketSameLine: false,
    sortPackageJson: false,
    ignorePatterns: [
      "package-lock.json",
      "pnpm-lock.yaml",
      "yarn.lock",
      "bun.lock",
      "bun.lockb",
      "/node_modules/",
      "/dist/",
    ],
  },
});
