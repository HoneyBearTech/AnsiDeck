// A fake navigator.credentials (and window.PublicKeyCredential) for the passkey UI: create() and get()
// resolve with fixed bytes, or reject with what a test hands them.
import { vi } from "vitest";

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer;
}

export const CREATED = {
  id: "AQID",
  rawId: "AQID",
  type: "public-key",
  response: { clientDataJSON: "BAU", attestationObject: "Bgc", transports: ["internal"] },
  authenticatorAttachment: "platform",
  clientExtensionResults: {},
};

export const ASSERTED = {
  id: "AQID",
  rawId: "AQID",
  type: "public-key",
  response: { clientDataJSON: "BAU", authenticatorData: "CAk", signature: "Cgs", userHandle: null },
  authenticatorAttachment: "platform",
  clientExtensionResults: {},
};

function credential(response: object) {
  return {
    id: "AQID",
    rawId: bytes(1, 2, 3),
    type: "public-key",
    response,
    authenticatorAttachment: "platform",
    getClientExtensionResults: () => ({}),
  };
}

export function fakeCredentials() {
  const create = vi.fn(async (_options: CredentialCreationOptions) =>
    credential({
      clientDataJSON: bytes(4, 5),
      attestationObject: bytes(6, 7),
      getTransports: () => ["internal"],
    }),
  );
  const get = vi.fn(async (_options: CredentialRequestOptions) =>
    credential({
      clientDataJSON: bytes(4, 5),
      authenticatorData: bytes(8, 9),
      signature: bytes(10, 11),
      userHandle: null,
    }),
  );
  // passkeysSupported() only checks that it exists.
  vi.stubGlobal("PublicKeyCredential", function PublicKeyCredential() {});
  Object.defineProperty(navigator, "credentials", { value: { create, get }, configurable: true });
  return { create, get };
}

// The server's options, as in PublicKeyCredential{Creation,Request}OptionsJSON.
export const CREATION_OPTIONS = {
  rp: { id: "localhost", name: "AnsiDeck" },
  user: { id: "AAEC", name: "admin", displayName: "admin" },
  challenge: "AwQF",
  pubKeyCredParams: [{ type: "public-key", alg: -7 }],
  excludeCredentials: [{ id: "BgcI", type: "public-key", transports: ["usb"] }],
};

export const REQUEST_OPTIONS = {
  rpId: "localhost",
  challenge: "AwQF",
  allowCredentials: [{ id: "AQID", type: "public-key" }],
  userVerification: "discouraged",
};
