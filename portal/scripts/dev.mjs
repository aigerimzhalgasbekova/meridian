// Boots server (in-memory repos + outbox mail) and web (vite) together.
// ponytail: plain child_process instead of a `concurrently` dependency.
import { spawn } from 'node:child_process';

const procs = [
  spawn('npm', ['run', 'dev', '-w', 'server'], { stdio: 'inherit' }),
  spawn('npm', ['run', 'dev', '-w', 'web'], { stdio: 'inherit' }),
];

const stop = () => procs.forEach((p) => p.kill('SIGTERM'));
process.on('SIGINT', stop);
process.on('SIGTERM', stop);
for (const p of procs) p.on('exit', (code) => { if (code) { stop(); process.exit(code); } });
