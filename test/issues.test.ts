import assert from "node:assert/strict";
import { test } from "vite-plus/test";

import { AuthIssueEvent, createIssue, createIssueFactory } from "../src/issues/index.js";

class DemoIssueEvent extends AuthIssueEvent<{ email: string; name: string }> {
  constructor() {
    super(["email", "name"] as const);
  }
}

test("createIssue omits empty paths", () => {
  const root = createIssue("boom");
  const empty = createIssue("boom", []);
  const nested = createIssue("invalid", ["payload", "email"]);

  assert.deepEqual(root, { message: "boom" });
  assert.deepEqual(empty, { message: "boom" });
  assert.deepEqual(nested, { message: "invalid", path: ["payload", "email"] });
});

test("issue factory creates field helpers and root/path helpers", () => {
  const factory = createIssueFactory<{ email: string; name: string }>(["email", "name"] as const);

  assert.deepEqual(factory.email("Invalid email"), {
    message: "Invalid email",
    path: ["email"],
  });
  assert.deepEqual(factory.name("Name missing"), {
    message: "Name missing",
    path: ["name"],
  });
  assert.deepEqual(factory.$root("Bad"), { message: "Bad" });
  assert.deepEqual(factory.$path(["items", { index: 1 }, "name"], "Nope"), {
    message: "Nope",
    path: ["items", { index: 1 }, "name"],
  });
});

test("AuthIssueEvent cancel overloads collect issues consistently", () => {
  const event = new DemoIssueEvent();
  event.addIssues(event.issue.email("Invalid email"));

  event.cancel("Stopped", event.issue.name("Name required"));
  assert.equal(event.canceled, true);
  assert.equal(event.reason, "Stopped");
  assert.equal(event.issues.length, 2);

  const event2 = new DemoIssueEvent();
  event2.cancel(event2.issue.email("Bad"));
  assert.equal(event2.reason, "Bad");
  assert.deepEqual(event2.issues, [{ message: "Bad", path: ["email"] }]);
});
