// OpenPGP.js side of the cross-library interoperability test (protocol v1 §14).
// Plays a web client. Usage (inside a Node container with OpenPGP.js built):
//   node openpgpjs.mjs <openpgp.mjs path> <dir> step1|step2
// step1: reads sequoia_cert.bin; writes ojs_cert.bin, ojs_key.asc (test-only private key),
//        ojs_proof.sig (registration proof), ojs_session.sig (device-session proof) and
//        ojs_message.pgp (signed + encrypted to both certificates).
// step2: decrypts sequoia_reply.pgp with the OpenPGP.js key and checks Sequoia's signature.
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const [, , libPath, dir, step] = process.argv;
const openpgp = await import(libPath);
const read = (name) => new Uint8Array(readFileSync(join(dir, name)));
const params = JSON.parse(readFileSync(join(dir, 'params.json'), 'utf8'));

async function detached(privateKey, text) {
  const message = await openpgp.createMessage({ binary: new TextEncoder().encode(text) });
  return openpgp.sign({ message, signingKeys: privateKey, detached: true, format: 'binary' });
}

if (step === 'step1') {
  // The key must ADVERTISE SEIPDv2 and AES-256+OCB: OpenPGP.js only uses SEIPDv2 (and
  // AES-256) when every recipient key's self-signature does (protocol v1 §3.1, §6.2).
  const { privateKey } = await openpgp.generateKey({
    type: 'curve25519', userIDs: [], format: 'object',
    config: {
      v6Keys: true,
      aeadProtect: true,
      preferredAEADAlgorithm: openpgp.enums.aead.ocb,
      preferredSymmetricAlgorithm: openpgp.enums.symmetric.aes256,
    },
    keyExpirationTime: 365 * 86400, subkeys: [{ sign: true }, { type: 'pqc' }],
  });
  const publicKey = privateKey.toPublic();
  const fingerprint = publicKey.getFingerprint();
  writeFileSync(join(dir, 'ojs_cert.bin'), publicKey.write());
  writeFileSync(join(dir, 'ojs_key.asc'), privateKey.armor());
  const registration = `agnusmail/key-registration/v1\n${params.service}\n${params.account}\n${fingerprint}`;
  writeFileSync(join(dir, 'ojs_proof.sig'), await detached(privateKey, registration));
  const session = `agnusmail/device-session/v1\n${params.service}\n${fingerprint}\n${params.challenge}`;
  writeFileSync(join(dir, 'ojs_session.sig'), await detached(privateKey, session));

  const sequoia = await openpgp.readKey({ binaryKey: read('sequoia_cert.bin') });
  // Protocol v1 §6.2: senders use FIXED parameters (SEIPDv2, AES-256, OCB) instead of
  // negotiating from recipient preferences: OpenPGP.js does not apply RFC 9980 §7.1's
  // implicit AES-256+OCB and would fall back to AES-128. Passing the session key with its
  // algorithms is OpenPGP.js public API.
  const sessionKey = {
    data: crypto.getRandomValues(new Uint8Array(32)),
    algorithm: 'aes256',
    aeadAlgorithm: 'ocb',
  };
  const encrypted = await openpgp.encrypt({
    message: await openpgp.createMessage({ binary: new TextEncoder().encode(params.plaintext) }),
    encryptionKeys: [sequoia, publicKey], signingKeys: privateKey, format: 'binary',
    sessionKey,
  });
  writeFileSync(join(dir, 'ojs_message.pgp'), encrypted);
  console.log(JSON.stringify({ step, fingerprint }));
} else if (step === 'step2') {
  const privateKey = await openpgp.readPrivateKey({ armoredKey: readFileSync(join(dir, 'ojs_key.asc'), 'utf8') });
  const sequoia = await openpgp.readKey({ binaryKey: read('sequoia_cert.bin') });
  const message = await openpgp.readMessage({ binaryMessage: read('sequoia_reply.pgp') });
  const { data, signatures } = await openpgp.decrypt({
    message, decryptionKeys: privateKey, verificationKeys: sequoia, format: 'binary',
  });
  await signatures[0].verified; // throws if the signature does not verify
  const text = new TextDecoder().decode(data);
  if (text !== params.reply) throw new Error('reply plaintext mismatch');
  console.log(JSON.stringify({ step, decrypted: true, signature: 'valid' }));
} else {
  throw new Error(`unknown step ${step}`);
}
