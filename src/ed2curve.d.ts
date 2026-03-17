declare module "ed2curve" {
  export function convertPublicKey(
    ed25519Pub: Uint8Array,
  ): Uint8Array | null;
  export function convertSecretKey(
    ed25519Secret: Uint8Array,
  ): Uint8Array | null;
  export function convertKeyPair(keyPair: {
    publicKey: Uint8Array;
    secretKey: Uint8Array;
  }): { publicKey: Uint8Array; secretKey: Uint8Array } | null;
}
