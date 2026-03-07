/**
 * @see https://prettier.io/docs/configuration
 * @type {import("prettier").Config}
 */
const config = {
  trailingComma: "all",
  tabWidth: 2,
  semi: true,
  singleQuote: false,
  printWidth: 120,
  arrowParens: "always",
  bracketSpacing: true,
  bracketSameLine: false,
  bracketSpacing: true,
  plugins: ["prettier-plugin-organize-imports"],
};

export default config;
