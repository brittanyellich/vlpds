// Test-only card service for the native repository integration target. No
// credentials are read; its ephemeral private sender key is never exported.
import { generateKeyPairSync } from 'node:crypto';
import { createPilot, openLedger, agentDid, principalDid } from '../pilot.mjs';

const [publicOrigin, encodedPort] = process.argv.slice(2);
const port = Number(encodedPort);
if (!Number.isInteger(port) || port < 1024 || port > 65535) throw new Error('Fixture port required');
const keys = generateKeyPairSync('ed25519');
const ledger = openLedger(':memory:');
const server = createPilot({ enabled: true, publicOrigin, ledger,
  senders: [{ sender: 'repository-fixture', keyId: 'ephemeral',
    publicKeyPem: keys.publicKey.export({ format: 'pem', type: 'spki' }) }],
  dispatch: async () => ({ agentDid, principalDid, status: 'declared_unverified' }),
});
server.listen(port, '127.0.0.1');
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close(() => ledger.close()));
