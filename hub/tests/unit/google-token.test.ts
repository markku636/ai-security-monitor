import { beforeAll, expect, it, vi } from 'vitest';
import { generateKeyPair, SignJWT } from 'jose';
import { googleLoginConfig, verifyGoogleIdToken } from '@/lib/auth/google';
const keys = vi.hoisted(() => ({ publicKey: undefined as CryptoKey | undefined }));
vi.mock('jose', async (original) => ({ ...(await original<typeof import('jose')>()), createRemoteJWKSet: () => keys.publicKey }));
let privateKey: CryptoKey;
beforeAll(async () => { const pair = await generateKeyPair('RS256'); privateKey = pair.privateKey; keys.publicKey = pair.publicKey; });
const cfg = { ...googleLoginConfig(), issuer: 'https://accounts.google.com', clientId: 'client' };
const discovery = { issuer: cfg.issuer, authorization_endpoint: '', token_endpoint: '', jwks_uri: 'https://www.googleapis.com/oauth2/v3/certs' };
async function token(overrides: Record<string, unknown> = {}) {
  return new SignJWT({ iss: cfg.issuer, aud: 'client', sub: 'subject', nonce: 'nonce', exp: Math.floor(Date.now() / 1000) + 60, ...overrides }).setProtectedHeader({ alg: 'RS256' }).sign(privateKey);
}
it('accepts a valid Google-signed token and both documented issuers', async () => {
  for (const iss of ['https://accounts.google.com', 'accounts.google.com']) {
    expect((await verifyGoogleIdToken(await token({ iss }), discovery, cfg, 'nonce')).sub).toBe('subject');
  }
});
it.each([
  { iss: 'https://attacker.example' }, { aud: 'another-client' }, { nonce: 'wrong' },
  { exp: 1 }, { sub: '' }, { azp: 'another-client' },
])('rejects invalid claims %j', async (claims) => {
  await expect(verifyGoogleIdToken(await token(claims), discovery, cfg, 'nonce')).rejects.toThrow();
});
it('rejects a forged signature', async () => {
  const attacker = await generateKeyPair('RS256');
  const forged = await new SignJWT({ iss: cfg.issuer, aud: 'client', sub: 'x', nonce: 'nonce' }).setProtectedHeader({ alg: 'RS256' }).sign(attacker.privateKey);
  await expect(verifyGoogleIdToken(forged, discovery, cfg, 'nonce')).rejects.toThrow();
});
