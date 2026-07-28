import assert from "node:assert/strict";
import test from "node:test";

process.env.NODE_ENV = "test";
process.env.CLOUDBASE_ENV_ID = "test-environment";
process.env.JWT_SECRET = "test-jwt-secret-that-is-at-least-32-characters";
process.env.PII_ENCRYPTION_KEY = "0".repeat(64);
process.env.PII_HASH_SECRET = "test-hash-secret-that-is-at-least-32-characters";
process.env.BOOTSTRAP_TOKEN = "test-bootstrap-token";

const { app } = await import("./index.js");

test("health endpoint responds without database access", async () => {
  const server = app.listen(0, "127.0.0.1");
  await new Promise((resolve) => server.once("listening", resolve));
  try {
    const address = server.address();
    const response = await fetch(`http://127.0.0.1:${address.port}/api/health`);
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.equal(body.ok, true);
    assert.equal(body.service, "civic-volunteer-api");
  } finally {
    await new Promise((resolve, reject) =>
      server.close((error) => (error ? reject(error) : resolve())),
    );
  }
});
