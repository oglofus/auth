import { createIssue } from "../issues/index.js";
import { AuthError } from "../errors/index.js";

export const ensureFields = (
  source: Record<string, unknown>,
  fields: readonly string[],
  basePath: PropertyKey[] = [],
): AuthError | null => {
  const issues = fields
    .filter((field) => {
      const value = source[field];
      if (value === null || value === undefined) {
        return true;
      }
      if (typeof value === "string" && value.trim() === "") {
        return true;
      }
      return false;
    })
    .map((field) => createIssue(`${field} is required`, [...basePath, field]));

  if (issues.length === 0) {
    return null;
  }

  return new AuthError("INVALID_INPUT", "Missing required fields.", 400, issues);
};
