#!/usr/bin/env node
// Read-only hardware discovery. Discovery is never cryptographic attestation.
import { spawn } from 'node:child_process';
import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const DEFAULT_TIMEOUT_MS = 8_000;
const DEFAULT_OUTPUT_BYTES = 256 * 1024;
const USB_SECURITY_NAME = /\b(?:TPM|Trusted Platform|HSM|YubiKey|Yubico|Nitrokey|FIDO\d?|Security Key|Smart[ -]?Card|PKCS[ #_-]*11|Feitian|SoloKey|OpenPGP|Identiv|ACR\d+)\b/i;
const SAFE_TOOL_ENV = Object.freeze({ PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C', LC_ALL: 'C' });

function bounds(value, fallback, minimum, maximum) {
  return Number.isInteger(value) && value >= minimum && value <= maximum ? value : fallback;
}

/** Runs an argument array without a shell or inherited credentials. Raw output is internal only. */
export function runBoundedCommand(file, args, options = {}) {
  const timeoutMs = bounds(options.timeoutMs, DEFAULT_TIMEOUT_MS, 20, 15_000);
  const maxOutputBytes = bounds(options.maxOutputBytes, DEFAULT_OUTPUT_BYTES, 64, 1024 * 1024);
  return new Promise((resolve) => {
    let child;
    let timer;
    let complete = false;
    let totalBytes = 0;
    let stdout = '';
    const finish = (status, exitCode = null) => {
      if (complete) return;
      complete = true;
      clearTimeout(timer);
      if (status === 'timeout' || status === 'output_limit') {
        child?.kill('SIGKILL');
        child?.stdout?.destroy();
        child?.stderr?.destroy();
      }
      resolve({ status, exitCode, stdout });
    };
    try {
      child = spawn(file, args, {
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...SAFE_TOOL_ENV, ...(options.temporaryDirectory ? { TMPDIR: options.temporaryDirectory } : {}) },
      });
      timer = setTimeout(() => finish('timeout'), timeoutMs);
      const collect = (chunk, retain) => {
        if (complete) return;
        totalBytes += chunk.length;
        if (totalBytes > maxOutputBytes) return finish('output_limit');
        if (retain) stdout += chunk.toString('utf8');
      };
      child.stdout.on('data', (chunk) => collect(chunk, true));
      child.stderr.on('data', (chunk) => collect(chunk, false));
      child.once('error', () => finish('spawn_error'));
      child.once('close', (code) => finish(code === 0 ? 'ok' : 'nonzero_exit', code));
    } catch {
      finish('spawn_error');
    }
  });
}

function usbId(value) {
  if (typeof value !== 'string') return null;
  const match = value.match(/^0x([a-f\d]{4})(?:\s|$)/i);
  return match ? `0x${match[1].toLowerCase()}` : null;
}

function securityProductName(value) {
  if (typeof value !== 'string' || value.length > 120 || !USB_SECURITY_NAME.test(value)) return null;
  // Avoid returning serial numbers, UUIDs, paths, or personal names embedded in a device label.
  if (/['’"/\\@]|\bserial\b|\b[0-9a-f]{8}-[0-9a-f-]{27,}\b|\b\d{7,}\b/i.test(value)) return null;
  if (!/^[\p{L}\p{N} ._+(),#-]+$/u.test(value)) return null;
  return value.replace(/\s+/g, ' ').trim();
}

/** Extracts only non-secret identifiers, never serial_num, UUID, location, or arbitrary USB fields. */
export function parseUsbInventory(raw, { maxOutputBytes = DEFAULT_OUTPUT_BYTES } = {}) {
  if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') > maxOutputBytes) {
    return { state: 'output_limit', devices: [] };
  }
  let source;
  try { source = JSON.parse(raw); } catch { return { state: 'invalid_json', devices: [] }; }
  if (!source || typeof source !== 'object' || !Array.isArray(source.SPUSBDataType)) {
    return { state: 'invalid_inventory', devices: [] };
  }
  const devices = [];
  const seen = new Set();
  const pending = source.SPUSBDataType.map((value) => ({ value, depth: 0 }));
  let inspected = 0;
  let limited = false;
  while (pending.length) {
    const { value, depth } = pending.pop();
    if (++inspected > 512 || devices.length >= 64 || depth > 16) { limited = true; break; }
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
    const vendorId = usbId(value.vendor_id);
    const productId = usbId(value.product_id);
    if (vendorId || productId) {
      const productName = securityProductName(value._name);
      const key = JSON.stringify([vendorId, productId, productName]);
      if (!seen.has(key)) {
        seen.add(key);
        devices.push({ productName, vendorId, productId, securityCandidate: Boolean(productName) });
      }
    }
    if (Array.isArray(value._items)) {
      for (const item of value._items.slice(0, 513)) pending.push({ value: item, depth: depth + 1 });
      if (value._items.length > 513) limited = true;
    }
  }
  return { state: limited ? 'inventory_limit' : 'read', devices };
}

async function fileIs(fsApi, file, type) {
  try {
    const stat = await fsApi.stat(file);
    return type === 'character' ? stat.isCharacterDevice() : stat.isFile();
  } catch { return false; }
}

async function executable(fsApi, file) {
  if (!await fileIs(fsApi, file, 'file')) return false;
  try { await fsApi.access(file, constants.X_OK); return true; } catch { return false; }
}

async function command(runner, file, args, options) {
  try {
    const result = await runner(file, args, options);
    if (!result || !['ok', 'nonzero_exit', 'timeout', 'output_limit', 'spawn_error'].includes(result.status)) {
      return { status: 'spawn_error', stdout: '' };
    }
    if (typeof result.stdout !== 'string' || Buffer.byteLength(result.stdout) > options.maxOutputBytes) {
      return { status: 'output_limit', stdout: '' };
    }
    return result;
  } catch { return { status: 'spawn_error', stdout: '' }; }
}

function normalizedPlatform(value) {
  return value === 'macos' ? 'darwin' : value;
}

function remediation(report) {
  if (!report.execution.matchesExpectedPlatform) {
    return ['Run this command on the computer where the device is connected; this result describes only the current process host.'];
  }
  const instructions = ['Discovery does not verify a hardware-backed key or authorize a live cryptographic provider.'];
  if (report.usb.devices.some((device) => /Yubi/i.test(device.productName ?? ''))) {
    instructions.push('A YubiKey is not a TPM. Confirm its exact model, firmware, and supported PIV or PKCS#11 integration before provisioning.');
  } else if (report.status === 'missing_hardware') {
    instructions.push('Run the probe on the hardware host and identify the device model before configuring a vendor PKCS#11 provider.');
  } else {
    instructions.push('Configure the repository-supported provider only after its device model and cryptographic capabilities are confirmed.');
  }
  if (report.host.platform === 'darwin') {
    instructions.push('Apple Secure Enclave is separate from a TPM or external HSM; availability is not an attested integration.');
  }
  return instructions;
}

/**
 * Probe the current host only. Injectable I/O keeps tests independent of real devices.
 * A positive observation always remains unverified until the actual provider verifies a key.
 */
export async function probeHardwareSecurity({
  platform = process.platform,
  arch = process.arch,
  expectedPlatform,
  fsApi = fs,
  runner = runBoundedCommand,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  maxOutputBytes = DEFAULT_OUTPUT_BYTES,
  checkSecureEnclave = false,
} = {}) {
  platform = normalizedPlatform(platform);
  expectedPlatform = normalizedPlatform(expectedPlatform);
  if (expectedPlatform && !['linux', 'darwin'].includes(expectedPlatform)) throw new Error('Unsupported expected platform.');
  const options = {
    timeoutMs: bounds(timeoutMs, DEFAULT_TIMEOUT_MS, 20, 15_000),
    maxOutputBytes: bounds(maxOutputBytes, DEFAULT_OUTPUT_BYTES, 64, 1024 * 1024),
  };
  const report = {
    schemaVersion: 1,
    host: { platform: ['linux', 'darwin'].includes(platform) ? platform : 'unsupported', architecture: /^[a-z\d_]{1,16}$/i.test(arch) ? arch : 'unknown', model: null },
    execution: { scope: 'current_process_host_only', expectedPlatform: expectedPlatform ?? null, matchesExpectedPlatform: !expectedPlatform || expectedPlatform === platform },
    status: 'missing_hardware',
    liveHardwareVerified: false,
    tpm: { devices: [], driver: null, capabilityRead: 'not_attempted', readiness: 'not_detected' },
    usb: { state: 'not_applicable', devices: [] },
    secureEnclave: { availability: 'unknown', state: platform === 'darwin' ? 'not_requested' : 'not_applicable', isTpm: false, isExternalHsm: false },
  };
  if (!report.execution.matchesExpectedPlatform || report.host.platform === 'unsupported') {
    report.remediation = remediation(report);
    return report;
  }
  if (platform === 'linux') {
    for (const device of ['/dev/tpmrm0', '/dev/tpm0']) {
      if (await fileIs(fsApi, device, 'character')) report.tpm.devices.push(device);
    }
    if (report.tpm.devices.length) {
      report.status = 'unverified_hardware';
      report.tpm.readiness = 'device_detected';
      try {
        const target = await fsApi.readlink('/sys/class/tpm/tpm0/device/driver');
        const driver = typeof target === 'string' && target.length <= 1024 ? path.basename(target) : '';
        if (/^[a-z\d_.-]{1,64}$/i.test(driver)) report.tpm.driver = driver;
      } catch { /* Optional sysfs driver metadata. */ }
      for (const tool of ['/usr/bin/tpm2_getcap', '/usr/local/bin/tpm2_getcap']) {
        if (!await executable(fsApi, tool)) continue;
        const capabilities = await command(runner, tool, ['properties-fixed', '-T', `device:${report.tpm.devices[0]}`], options);
        report.tpm.capabilityRead = capabilities.status === 'ok' ? 'read' : capabilities.status;
        if (capabilities.status === 'ok' && /TPM2_PT_FAMILY_INDICATOR\s*:[\s\S]{0,160}\b(?:0x322[Ee]3000|2\.0)\b/.test(capabilities.stdout)) {
          report.tpm.readiness = 'device_and_tool_ready';
        }
        break;
      }
    }
  } else {
    if (await executable(fsApi, '/usr/sbin/sysctl')) {
      const model = await command(runner, '/usr/sbin/sysctl', ['-n', 'hw.model'], options);
      const value = model.stdout.trim();
      if (model.status === 'ok' && /^(?:Mac\w*|iMac\w*|VirtualMac|Xserve)\d+,\d+$/.test(value) && value.length <= 40) report.host.model = value;
    }
    if (await executable(fsApi, '/usr/sbin/system_profiler')) {
      const inventory = await command(runner, '/usr/sbin/system_profiler', ['SPUSBDataType', '-json', '-detailLevel', 'mini'], options);
      report.usb = inventory.status === 'ok' ? parseUsbInventory(inventory.stdout, options) : { state: inventory.status, devices: [] };
      if (report.usb.devices.some((device) => device.securityCandidate)) report.status = 'unverified_hardware';
    } else report.usb.state = 'tool_unavailable';
    if (checkSecureEnclave) await probeSecureEnclave(report, fsApi, runner, options);
  }
  report.remediation = remediation(report);
  return report;
}

async function probeSecureEnclave(report, fsApi, runner, options) {
  report.secureEnclave.state = 'developer_tools_unavailable';
  if (!await executable(fsApi, '/usr/bin/xcode-select') || !await executable(fsApi, '/usr/bin/swift')) return;
  const selected = await command(runner, '/usr/bin/xcode-select', ['-p'], options);
  const developerPath = selected.stdout.trim();
  const appleToolchain = developerPath === '/Library/Developer/CommandLineTools' || /^\/Applications\/[^/]+\.app\/Contents\/Developer$/.test(developerPath);
  if (selected.status !== 'ok' || !appleToolchain || !await executable(fsApi, `${developerPath}/usr/bin/swift`)) return;
  let temporaryDirectory;
  try {
    // Compilation may create temporary caches; it never creates a key or changes device state.
    temporaryDirectory = await fsApi.mkdtemp(path.join(tmpdir(), 'dunesub-hardware-probe-'));
    const result = await command(runner, '/usr/bin/swift', [
      '-module-cache-path', temporaryDirectory,
      '-e', 'import CryptoKit; print(SecureEnclave.isAvailable ? "DUNESUB_SECURE_ENCLAVE_AVAILABLE" : "DUNESUB_SECURE_ENCLAVE_UNAVAILABLE")',
    ], { ...options, temporaryDirectory });
    if (result.status !== 'ok') { report.secureEnclave.state = result.status; return; }
    const answer = result.stdout.trim();
    if (!['DUNESUB_SECURE_ENCLAVE_AVAILABLE', 'DUNESUB_SECURE_ENCLAVE_UNAVAILABLE'].includes(answer)) {
      report.secureEnclave.state = 'unexpected_output';
      return;
    }
    report.secureEnclave.state = 'availability_read';
    report.secureEnclave.availability = answer.endsWith('_UNAVAILABLE') ? false : true;
    if (report.secureEnclave.availability) report.status = 'unverified_hardware';
  } catch { report.secureEnclave.state = 'probe_unavailable'; }
  finally {
    if (temporaryDirectory) {
      try { await fsApi.rm(temporaryDirectory, { recursive: true, force: true }); } catch { /* No private data was written. */ }
    }
  }
}

async function main() {
  const args = process.argv.slice(2);
  let expectedPlatform;
  let checkSecureEnclave = false;
  for (let index = 0; index < args.length; index++) {
    if (args[index] === '--help') {
      process.stdout.write('Usage: node scripts/hardware-security-probe.mjs [--expected-platform macos|linux] [--check-secure-enclave]\n');
      return;
    }
    if (args[index] === '--expected-platform' && ['macos', 'darwin', 'linux'].includes(args[index + 1])) expectedPlatform = args[++index];
    else if (args[index] === '--check-secure-enclave') checkSecureEnclave = true;
    else throw new Error('Unsupported probe argument. Use --help for accepted options.');
  }
  const report = await probeHardwareSecurity({ expectedPlatform, checkSecureEnclave });
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main().catch(() => {
    process.stderr.write('Hardware discovery could not complete. Use --help or run the probe on the hardware host.\n');
    process.exitCode = 1;
  });
}
