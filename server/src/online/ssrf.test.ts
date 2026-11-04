import test from "node:test";
import assert from "node:assert/strict";
import { OnlineError } from "./errors.js";
import {
  isBlockedIp,
  resolveAndValidateHost,
  validatePublicUrl,
  validateRedirectTarget,
} from "./ssrf.js";

test("isBlockedIp blocks loopback, private, and link-local IPv4", () => {
  for (const ip of [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "10.255.255.255",
    "172.16.0.1",
    "172.31.255.255",
    "192.168.0.1",
    "169.254.169.254",
    "0.0.0.0",
    "100.64.0.1",
    "224.0.0.1",
    "255.255.255.255",
    "240.0.0.1",
    "198.18.0.1",
    "192.0.2.1",
    "203.0.113.9",
  ]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test("isBlockedIp allows public IPv4", () => {
  for (const ip of ["93.184.216.34", "1.1.1.1", "8.8.8.8", "142.250.72.14", "172.15.9.9", "172.32.0.1"]) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test("isBlockedIp blocks non-global IPv6, including mapped and tunneled IPv4", () => {
  for (const ip of [
    "::1",
    "::",
    "fe80::1",
    "fc00::1",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.0.0.1",
    "::ffff:169.254.169.254",
    "64:ff9b::7f00:1",
    "2001::1",
    "2002:0a00:0001::1",
    "2001:db8::1",
    "100::1",
  ]) {
    assert.equal(isBlockedIp(ip), true, ip);
  }
});

test("isBlockedIp allows public IPv6", () => {
  for (const ip of ["2606:4700:4700::1111", "2001:4860:4860::8888", "::ffff:93.184.216.34"]) {
    assert.equal(isBlockedIp(ip), false, ip);
  }
});

test("isBlockedIp fails closed on garbage", () => {
  assert.equal(isBlockedIp("not-an-ip"), true);
  assert.equal(isBlockedIp("999.1.1.1"), true);
  assert.equal(isBlockedIp(""), true);
});

test("validatePublicUrl accepts http and https only", () => {
  assert.equal(validatePublicUrl("https://example.com/").hostname, "example.com");
  assert.equal(validatePublicUrl("http://example.com:8080/a?b=1").protocol, "http:");
  assert.equal(validatePublicUrl("  https://example.com  ").hostname, "example.com");
  for (const raw of [
    "file:///etc/passwd",
    "ftp://example.com/",
    "javascript:alert(1)",
    "gopher://example.com/",
    "https://user:pass@example.com/",
    "https://user@example.com/",
    "not a url",
    "",
    "example.com",
    "/relative/path",
  ]) {
    assert.throws(() => validatePublicUrl(raw), (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "invalid-url");
      assert.equal(err.status, 400);
      return true;
    }, raw);
  }
});

test("validatePublicUrl rejects over-long URLs", () => {
  assert.throws(() => validatePublicUrl(`https://example.com/${"a".repeat(2100)}`), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "invalid-url");
    return true;
  });
});

test("URL parser normalizes obfuscated loopback forms", () => {
  // WHATWG parsing turns decimal/hex/octal IPv4 into dotted form, so the
  // IP classifier sees the real address.
  assert.equal(validatePublicUrl("http://2130706433/").hostname, "127.0.0.1");
  assert.equal(validatePublicUrl("http://0x7f.0x0.0x0.0x1/").hostname, "127.0.0.1");
});

test("resolveAndValidateHost blocks literal private IPs without DNS", async () => {
  let resolverCalls = 0;
  const resolver = async (): Promise<string[]> => {
    resolverCalls += 1;
    return ["93.184.216.34"];
  };
  for (const host of ["127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "::ffff:10.0.0.1"]) {
    await assert.rejects(resolveAndValidateHost(host, resolver), (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      assert.equal(err.code, "blocked-host");
      return true;
    }, host);
  }
  assert.equal(resolverCalls, 0);
  await resolveAndValidateHost("93.184.216.34", resolver);
  assert.equal(resolverCalls, 0);
});

test("resolveAndValidateHost requires every resolved address to be public", async () => {
  const byHost: Record<string, string[]> = {
    "clean.example": ["93.184.216.34", "2606:4700:4700::1111"],
    "mixed.example": ["93.184.216.34", "10.0.0.9"],
    "evil.example": ["169.254.169.254"],
    "empty.example": [],
  };
  const resolver = async (host: string): Promise<string[]> => {
    if (!(host in byHost)) throw new Error("unexpected host");
    return byHost[host]!;
  };
  await resolveAndValidateHost("clean.example", resolver);
  await assert.rejects(resolveAndValidateHost("mixed.example", resolver), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    return true;
  });
  await assert.rejects(resolveAndValidateHost("evil.example", resolver), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "blocked-host");
    return true;
  });
  await assert.rejects(resolveAndValidateHost("empty.example", resolver), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "dns-failed");
    return true;
  });
  await assert.rejects(resolveAndValidateHost("missing.example", resolver), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "dns-failed");
    return true;
  });
});

test("resolveAndValidateHost rejects malformed hostnames", async () => {
  const resolver = async (): Promise<string[]> => ["93.184.216.34"];
  for (const host of ["exa mple.com", "a".repeat(300), "-bad-.com"]) {
    await assert.rejects(resolveAndValidateHost(host, resolver), (err: unknown) => {
      assert.ok(err instanceof OnlineError);
      return true;
    }, host);
  }
});

test("validateRedirectTarget resolves relative targets and re-checks scheme", () => {
  const current = validatePublicUrl("https://example.com/a");
  assert.equal(validateRedirectTarget(current, "/b").href, "https://example.com/b");
  assert.equal(validateRedirectTarget(current, "https://other.com/x").hostname, "other.com");
  assert.equal(validateRedirectTarget(current, "http://example.com/downgrade").protocol, "http:");
  assert.throws(() => validateRedirectTarget(current, "https://user:pw@example.com/"), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "invalid-url");
    return true;
  });
  assert.throws(() => validateRedirectTarget(current, "file:///etc/passwd"), (err: unknown) => {
    assert.ok(err instanceof OnlineError);
    assert.equal(err.code, "invalid-url");
    return true;
  });
});
