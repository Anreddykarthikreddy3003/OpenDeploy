// Browser WebAuthn helpers: convert the server's JSON options (base64url
// buffers) to/from the credential APIs.

function b64urlToBuf(s: string): ArrayBuffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b = atob((s + pad).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) out[i] = b.charCodeAt(i);
  return out.buffer;
}

function bufToB64url(buf: ArrayBuffer | null | undefined): string | undefined {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function webauthnSupported(): boolean {
  return typeof window !== "undefined" && !!window.PublicKeyCredential && !!navigator.credentials;
}

export async function createCredential(options: any): Promise<any> {
  const pk = { ...options.publicKey };
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.user = { ...pk.user, id: b64urlToBuf(pk.user.id) };
  pk.excludeCredentials = (pk.excludeCredentials ?? []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) }));
  const cred = (await navigator.credentials.create({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No credential was created");
  const r = cred.response as AuthenticatorAttestationResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      attestationObject: bufToB64url(r.attestationObject),
      transports: typeof r.getTransports === "function" ? r.getTransports() : undefined,
    },
  };
}

export async function getAssertion(options: any): Promise<any> {
  const pk = { ...options.publicKey };
  pk.challenge = b64urlToBuf(pk.challenge);
  pk.allowCredentials = (pk.allowCredentials ?? []).map((c: any) => ({ ...c, id: b64urlToBuf(c.id) }));
  const cred = (await navigator.credentials.get({ publicKey: pk })) as PublicKeyCredential | null;
  if (!cred) throw new Error("No security key response");
  const r = cred.response as AuthenticatorAssertionResponse;
  return {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64url(r.clientDataJSON),
      authenticatorData: bufToB64url(r.authenticatorData),
      signature: bufToB64url(r.signature),
      userHandle: bufToB64url(r.userHandle),
    },
  };
}
