import test from "node:test";
import assert from "node:assert/strict";
import { canTransition } from "../src/services/transitions.js";

test("valid lifecycle transitions", () => {
  assert.ok(canTransition("new", "acknowledged"));
  assert.ok(canTransition("acknowledged", "resolved"));
  assert.ok(canTransition("acknowledged", "blocked"));
  assert.ok(canTransition("acknowledged", "false_positive"));
});
test("invalid transitions are rejected", () => {
  assert.equal(canTransition("new", "blocked"), false);      // no block without acknowledgement
  assert.equal(canTransition("resolved", "new"), false);
  assert.equal(canTransition("blocked", "resolved"), false);
});
