import { describe, expect, it } from "vitest";
import { humanize, safeReturnPath, shorten } from "./format";

describe("safeReturnPath (no open redirects after sign-in)", () => {
  it.each([
    ["/cases/A-1042", "/cases/A-1042"],
    ["/alerts?status=open", "/alerts?status=open"],
    ["//evil.example", "/"],
    ["/\\evil.example", "/"],
    ["https://evil.example", "/"],
    ["javascript:alert(1)", "/"],
    [null, "/"],
    ["", "/"],
  ])("%s -> %s", (input, expected) => {
    expect(safeReturnPath(input)).toBe(expected);
  });
});

describe("formatting", () => {
  it("humanizes statuses and shortens long ids", () => {
    expect(humanize("awaiting_approval")).toBe("awaiting approval");
    expect(shorten("TQ7mWx3ZkP9vRb2LnH8sYcD4fGu6JtA1Ke")).toBe("TQ7mWx…A1Ke");
    expect(shorten("C-2291")).toBe("C-2291");
  });
});
