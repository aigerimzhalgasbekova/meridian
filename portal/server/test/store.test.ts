import { describe } from 'vitest';
import { memoryStore } from '../src/store/memory.js';
import { runStoreContract } from './contract/store.js';

// The memory store backs every API test, so it is the reference implementation
// of the contract. postgres runs the same suite in pg.test.ts.
describe('memory store', () => {
  runStoreContract(() => memoryStore());
});
