import { describe, expect, it } from "vitest";

import { ASSERTED, CREATED, CREATION_OPTIONS, fakeCredentials, REQUEST_OPTIONS } from "@/test/webauthn";

import {
  createPasskey,
  fromBase64url,
  getPasskey,
  passkeyProblem,
  passkeysSupported,
  toBase64url,
} from "./webauthn";

describe("webauthn", () => {
  it("round-trips base64url without padding", () => {
    for (const length of [0, 1, 2, 3, 4, 31, 32]) {
      const data = new Uint8Array(Array.from({ length }, (_, i) => (i * 97 + 251) % 256));
      const encoded = toBase64url(data.buffer);
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/);
      expect(new Uint8Array(fromBase64url(encoded))).toEqual(data);
    }
    expect(toBase64url(new Uint8Array([0xfb, 0xff]).buffer)).toBe("-_8");
  });

  it("hands the browser binary options and the server JSON", async () => {
    expect(passkeysSupported()).toBe(false);
    const { create, get } = fakeCredentials();
    expect(passkeysSupported()).toBe(true);

    expect(await createPasskey(CREATION_OPTIONS)).toEqual(CREATED);
    const publicKey = create.mock.calls[0]![0].publicKey!;
    expect(new Uint8Array(publicKey.challenge as ArrayBuffer)).toEqual(new Uint8Array([3, 4, 5]));
    expect(new Uint8Array(publicKey.user.id as ArrayBuffer)).toEqual(new Uint8Array([0, 1, 2]));
    expect(publicKey.excludeCredentials?.[0]).toMatchObject({ type: "public-key", transports: ["usb"] });
    expect(publicKey.rp).toEqual(CREATION_OPTIONS.rp);

    expect(await getPasskey(REQUEST_OPTIONS)).toEqual(ASSERTED);
    const request = get.mock.calls[0]![0].publicKey!;
    expect(new Uint8Array(request.allowCredentials![0]!.id as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]));
    expect(request.userVerification).toBe("discouraged");
  });

  it("explains what the browser refused", () => {
    expect(passkeyProblem(new DOMException("x", "NotAllowedError"))).toMatch(/closed or timed out/);
    expect(passkeyProblem(new DOMException("x", "InvalidStateError"))).toMatch(/already registered/);
    expect(passkeyProblem(new DOMException("x", "SecurityError"))).toMatch(/usual address/);
    expect(passkeyProblem(new DOMException("x", "AbortError"))).toMatch(/AbortError/);
    expect(passkeyProblem(new Error("x"))).toBeNull();
  });
});
