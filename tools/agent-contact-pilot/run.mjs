import { readFileSync, statSync } from 'node:fs';
import { createPilot, kodyDispatch, openLedger } from './pilot.mjs';

process.umask(0o077);
const path = process.argv[2];
if (!path) throw new Error('Pass an operator-owned local configuration file');
if (statSync(path).mode & 0o077) throw new Error('Local configuration must be owner-only');
const config = JSON.parse(readFileSync(path, 'utf8'));
if (config.enabled !== true || !Number.isInteger(config.port) || config.port < 1024 ||
    config.port > 65535 || typeof config.database !== 'string' || !config.database.startsWith('/')) {
  throw new Error('Explicit opt-in, local port and absolute SQLite path required');
}
const ledger = openLedger(config.database);
const server = createPilot({ enabled: true, senders: config.senders, ledger,
  dispatch: kodyDispatch(config.kodyEndpoint), publicOrigin: config.publicOrigin });
server.listen(config.port, '127.0.0.1', () => console.log('EXP-710 local identity resolver ready'));
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => server.close(() => ledger.close()));
