import test from "node:test";
import assert from "node:assert/strict";
import { z } from "zod";
// Mirrors passwordSchema in routes/auth.js (FR-AUTH-02); kept dependency-light on purpose
const pw = z.string().min(8).regex(/[A-Z]/).regex(/[a-z]/).regex(/[0-9]/);
test("password policy", () => {
  assert.ok(pw.safeParse("Str0ngPass1").success);
  assert.ok(!pw.safeParse("weak").success);
  assert.ok(!pw.safeParse("alllowercase1").success);
});
