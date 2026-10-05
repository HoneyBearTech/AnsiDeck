import { describe, expect, it } from "vitest";

import { commitLink, isSshUrl, shortSha } from "./git";

describe("git helpers", () => {
  it("shortens commits", () => {
    expect(shortSha("0123456789abcdef")).toBe("01234567");
    expect(shortSha(null)).toBe("");
  });

  it("links commits on GitHub-like forges and on GitLab", () => {
    expect(commitLink("https://github.com/o/r/", "abc")).toBe("https://github.com/o/r/commit/abc");
    expect(commitLink("https://gitlab.example/o/r", "abc")).toBe("https://gitlab.example/o/r/-/commit/abc");
    expect(commitLink(null, "abc")).toBeNull();
    expect(commitLink("https://github.com/o/r", null)).toBeNull();
  });

  it("recognises SSH remotes", () => {
    expect(isSshUrl("git@github.com:o/r.git")).toBe(true);
    expect(isSshUrl("ssh://git@host/o/r.git")).toBe(true);
    expect(isSshUrl("https://github.com/o/r.git")).toBe(false);
    expect(isSshUrl("https://user@host:443/o/r.git")).toBe(false);
  });
});
