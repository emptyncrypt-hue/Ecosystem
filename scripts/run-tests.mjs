#!/usr/bin/env node
import { readdir } from 'node:fs/promises';

// Loading node:test suites directly avoids version-specific isolation flags and
// runs them in this process on both Node 22 and newer LTS releases.
const directory = new URL('../test/', import.meta.url);
const files = (await readdir(directory, { withFileTypes: true }))
  .filter(entry => entry.isFile() && entry.name.endsWith('.test.mjs'))
  .map(entry => entry.name)
  .sort();
if (files.length === 0) throw new Error('No test suites were found.');
for (const filename of files) await import(new URL(filename, directory).href);
