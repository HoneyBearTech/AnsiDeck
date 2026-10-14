// Passkeys in the browser: the server's options JSON (base64url fields) to navigator.credentials, and
// the credential back to JSON for the server. Hand-rolled rather than relying on
// PublicKeyCredential.parse*OptionsFromJSON / toJSON(), which not every supported browser has yet.

import type { PasskeyOptionsJSON, PasskeyResponseJSON } from "@/lib/api";

type Descriptor = { id: string; type: string; transports?: string[] };

export function passkeysSupported(): boolean {
  return typeof window !== "undefined" && "PublicKeyCredential" in window && !!navigator.credentials;
}

export function fromBase64url(value: string): ArrayBuffer {
  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/")
    .padEnd(Math.ceil(value.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

export function toBase64url(buffer: ArrayBuffer): string {
  let binary = "";
  for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function descriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return (list as Descriptor[]).map((d) => ({
    id: fromBase64url(d.id),
    type: "public-key",
    ...(d.transports ? { transports: d.transports as AuthenticatorTransport[] } : {}),
  }));
}

export async function createPasskey(options: PasskeyOptionsJSON): Promise<PasskeyResponseJSON> {
  const user = options["user"] as { id: string; name: string; displayName: string };
  const publicKey = {
    ...options,
    challenge: fromBase64url(options["challenge"] as string),
    user: { ...user, id: fromBase64url(user.id) },
    excludeCredentials: descriptors(options["excludeCredentials"]),
  } as PublicKeyCredentialCreationOptions;
  const credential = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException("No passkey was created", "NotAllowedError");
  const response = credential.response as AuthenticatorAttestationResponse;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      attestationObject: toBase64url(response.attestationObject),
      transports: response.getTransports?.() ?? [],
    },
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
}

export async function getPasskey(options: PasskeyOptionsJSON): Promise<PasskeyResponseJSON> {
  const publicKey = {
    ...options,
    challenge: fromBase64url(options["challenge"] as string),
    allowCredentials: descriptors(options["allowCredentials"]),
  } as PublicKeyCredentialRequestOptions;
  const credential = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!credential) throw new DOMException("No passkey was used", "NotAllowedError");
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: credential.id,
    rawId: toBase64url(credential.rawId),
    type: credential.type,
    response: {
      clientDataJSON: toBase64url(response.clientDataJSON),
      authenticatorData: toBase64url(response.authenticatorData),
      signature: toBase64url(response.signature),
      userHandle: response.userHandle ? toBase64url(response.userHandle) : null,
    },
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults?.() ?? {},
  };
}

// What to tell the user when the browser's passkey prompt fails (the server's own errors are ApiErrors).
export function passkeyProblem(err: unknown): string | null {
  if (!(err instanceof DOMException)) return null;
  if (err.name === "NotAllowedError") return "The passkey prompt was closed or timed out. Try again.";
  if (err.name === "InvalidStateError") return "That passkey is already registered here.";
  if (err.name === "SecurityError")
    return "Passkeys don't work at this address. Open AnsiDeck at its usual address.";
  return `Your browser couldn't use a passkey (${err.name}).`;
}
