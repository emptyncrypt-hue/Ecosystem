import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parseUsbInventory, probeHardwareSecurity, runBoundedCommand } from '../scripts/hardware-security-probe.mjs';

function fakeFs({ files = [], characters = [], links = {} } = {}) {
  return {
    async stat(file) {
      if (!files.includes(file) && !characters.includes(file)) throw new Error('not found');
      return { isFile: () => files.includes(file), isCharacterDevice: () => characters.includes(file) };
    },
    async access(file) { if (!files.includes(file)) throw new Error('not executable'); },
    async readlink(file) { if (!(file in links)) throw new Error('not found'); return links[file]; },
    async mkdtemp() { return '/tmp/dunesub-test-compiler'; },
    async rm() {},
  };
}

const ok = (stdout) => ({ status: 'ok', exitCode: 0, stdout });
const usbReport = (items) => JSON.stringify({ SPUSBDataType: [{ _name: 'USB31Bus', _items: items }] });
const yubikey = { _name: 'YubiKey OTP+FIDO+CCID', vendor_id: '0x1050 (Yubico)', product_id: '0x0407', serial_num: 'PRIVATE-SERIAL-999999', location_id: 'PRIVATE-LOCATION', manufacturer: 'Yubico' };
const macTools = ['/usr/sbin/sysctl', '/usr/sbin/system_profiler'];

test('USB discovery keeps security product identifiers without serial, location, or unrelated personal names', () => {
  const result = parseUsbInventory(usbReport([
    { _name: 'USB Hub', _items: [yubikey] },
    { _name: "Alice’s iPhone", vendor_id: '0x05ac (Apple)', product_id: '0x1234', serial_num: 'PRIVATE-PHONE-SERIAL' },
  ]));
  assert.equal(result.state, 'read');
  assert.deepEqual(result.devices.find((device) => device.vendorId === '0x1050'), {
    productName: 'YubiKey OTP+FIDO+CCID', vendorId: '0x1050', productId: '0x0407', securityCandidate: true,
  });
  assert.equal(result.devices.find((device) => device.vendorId === '0x05ac').productName, null);
  assert.doesNotMatch(JSON.stringify(result), /Alice|PRIVATE|manufacturer|serial_num|location_id/);
});

test('device labels cannot sneak serial numbers, UUIDs, paths, email, or personal names into the report', () => {
  const names = ['YubiKey serial 12345', 'YubiKey 123456789', 'YubiKey /Users/alice', "Alice's YubiKey", 'YubiKey alice@example.test', 'YubiKey 123e4567-e89b-12d3-a456-426614174000'];
  const result = parseUsbInventory(usbReport(names.map((name, index) => ({ _name: name, vendor_id: '0x1050', product_id: `0x000${index}` }))));
  assert.equal(result.devices.length, names.length);
  assert.ok(result.devices.every((device) => device.productName === null && !device.securityCandidate));
  assert.doesNotMatch(JSON.stringify(result), /alice|Alice|123456789|123e4567/);
});

test('USB parser bounds malformed, oversized, deep, and excessive inventory', () => {
  assert.equal(parseUsbInventory('not JSON').state, 'invalid_json');
  assert.equal(parseUsbInventory('{}').state, 'invalid_inventory');
  assert.equal(parseUsbInventory(' '.repeat(1025), { maxOutputBytes: 1024 }).state, 'output_limit');
  let nested = yubikey;
  for (let index = 0; index < 20; index++) nested = { _items: [nested] };
  assert.equal(parseUsbInventory(usbReport([nested])).state, 'inventory_limit');
  const many = Array.from({ length: 100 }, (_, index) => ({ _name: 'FIDO Security Key', vendor_id: '0x1050', product_id: `0x${index.toString(16).padStart(4, '0')}` }));
  const result = parseUsbInventory(usbReport(many));
  assert.equal(result.state, 'inventory_limit');
  assert.equal(result.devices.length, 64);
});

test('a YubiKey on macOS is an unverified candidate, never a TPM or attested hardware key', async () => {
  const calls = [];
  const report = await probeHardwareSecurity({
    platform: 'darwin', arch: 'arm64', expectedPlatform: 'macos', fsApi: fakeFs({ files: macTools }),
    runner: async (file, args) => { calls.push({ file, args }); return ok(file.endsWith('sysctl') ? 'Mac14,7\n' : usbReport([yubikey])); },
  });
  assert.equal(report.host.model, 'Mac14,7');
  assert.equal(report.host.platform, 'darwin');
  assert.equal(report.status, 'unverified_hardware');
  assert.equal(report.liveHardwareVerified, false);
  assert.deepEqual(report.tpm.devices, []);
  assert.equal(report.secureEnclave.state, 'not_requested');
  assert.match(report.remediation.join(' '), /YubiKey is not a TPM/);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/);
  assert.deepEqual(calls, [
    { file: '/usr/sbin/sysctl', args: ['-n', 'hw.model'] },
    { file: '/usr/sbin/system_profiler', args: ['SPUSBDataType', '-json', '-detailLevel', 'mini'] },
  ]);
});

test('macOS model and tool failures are summarized without raw diagnostics or personal hostnames', async () => {
  const report = await probeHardwareSecurity({
    platform: 'darwin', fsApi: fakeFs({ files: macTools }),
    runner: async (file) => file.endsWith('sysctl') ? ok('Alice-MacBook.local\n') : ({ status: 'nonzero_exit', stdout: 'PRIVATE diagnostic /Users/alice', exitCode: 1 }),
  });
  assert.equal(report.host.model, null);
  assert.equal(report.usb.state, 'nonzero_exit');
  assert.equal(report.status, 'missing_hardware');
  assert.doesNotMatch(JSON.stringify(report), /Alice|alice|PRIVATE/);
});

test('oversized output from an injected tool is still refused', async () => {
  const report = await probeHardwareSecurity({
    platform: 'darwin', fsApi: fakeFs({ files: ['/usr/sbin/system_profiler'] }), maxOutputBytes: 1024,
    runner: async () => ok(' '.repeat(1025)),
  });
  assert.equal(report.usb.state, 'output_limit');
  assert.deepEqual(report.usb.devices, []);
});

test('Secure Enclave probe never launches Swift without an already installed selected Apple toolchain', async () => {
  const calls = [];
  const report = await probeHardwareSecurity({
    platform: 'darwin', checkSecureEnclave: true,
    fsApi: fakeFs({ files: ['/usr/bin/xcode-select', '/usr/bin/swift'] }),
    runner: async (file) => { calls.push(file); return ok('/Library/Developer/CommandLineTools\n'); },
  });
  assert.equal(report.secureEnclave.availability, 'unknown');
  assert.equal(report.secureEnclave.state, 'developer_tools_unavailable');
  assert.deepEqual(calls, ['/usr/bin/xcode-select']);
  assert.equal(report.liveHardwareVerified, false);
});

test('available Apple Secure Enclave stays explicitly separate from a verified TPM or HSM integration', async () => {
  const calls = [];
  const removals = [];
  const fsApi = fakeFs({ files: ['/usr/bin/xcode-select', '/usr/bin/swift', '/Library/Developer/CommandLineTools/usr/bin/swift'] });
  fsApi.rm = async (directory, options) => removals.push({ directory, options });
  const report = await probeHardwareSecurity({
    platform: 'darwin', checkSecureEnclave: true, fsApi,
    runner: async (file, args, options) => {
      calls.push({ file, args, options });
      return ok(file.endsWith('xcode-select') ? '/Library/Developer/CommandLineTools\n' : 'DUNESUB_SECURE_ENCLAVE_AVAILABLE\n');
    },
  });
  assert.deepEqual(report.secureEnclave, { availability: true, state: 'availability_read', isTpm: false, isExternalHsm: false });
  assert.equal(report.liveHardwareVerified, false);
  assert.equal(report.status, 'unverified_hardware');
  const swift = calls.find((call) => call.file === '/usr/bin/swift');
  assert.match(swift.args.at(-1), /SecureEnclave\.isAvailable/);
  assert.doesNotMatch(swift.args.at(-1), /PrivateKey|sign|encrypt|generate/i);
  assert.equal(swift.options.temporaryDirectory, '/tmp/dunesub-test-compiler');
  assert.deepEqual(removals, [{ directory: '/tmp/dunesub-test-compiler', options: { recursive: true, force: true } }]);
});

test('Secure Enclave tool timeout remains unknown and cleans temporary compiler files', async () => {
  let cleaned = false;
  const fsApi = fakeFs({ files: ['/usr/bin/xcode-select', '/usr/bin/swift', '/Library/Developer/CommandLineTools/usr/bin/swift'] });
  fsApi.rm = async () => { cleaned = true; };
  const report = await probeHardwareSecurity({
    platform: 'darwin', checkSecureEnclave: true, fsApi,
    runner: async (file) => file.endsWith('xcode-select') ? ok('/Library/Developer/CommandLineTools') : { status: 'timeout', stdout: 'PRIVATE compiler error' },
  });
  assert.equal(report.secureEnclave.availability, 'unknown');
  assert.equal(report.secureEnclave.state, 'timeout');
  assert.equal(cleaned, true);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE/);
});

test('TPM path existence as a regular file is insufficient and causes no tool command', async () => {
  const report = await probeHardwareSecurity({
    platform: 'linux', fsApi: fakeFs({ files: ['/dev/tpm0', '/dev/tpmrm0', '/usr/bin/tpm2_getcap'] }),
    runner: async () => { throw new Error('should not run'); },
  });
  assert.equal(report.status, 'missing_hardware');
  assert.deepEqual(report.tpm.devices, []);
  assert.equal(report.liveHardwareVerified, false);
});

test('Linux TPM device and local fixed-property read establish readiness without attestation', async () => {
  const calls = [];
  const report = await probeHardwareSecurity({
    platform: 'linux', arch: 'x64',
    fsApi: fakeFs({ characters: ['/dev/tpmrm0', '/dev/tpm0'], files: ['/usr/bin/tpm2_getcap'], links: { '/sys/class/tpm/tpm0/device/driver': '../../../../bus/platform/drivers/tpm_crb' } }),
    runner: async (file, args) => { calls.push({ file, args }); return ok('TPM2_PT_FAMILY_INDICATOR:\n  raw: 0x322E3000\n  value: "2.0"\nTPM2_PT_VENDOR_STRING_1: PRIVATE-VENDOR'); },
  });
  assert.equal(report.tpm.driver, 'tpm_crb');
  assert.equal(report.tpm.readiness, 'device_and_tool_ready');
  assert.equal(report.tpm.capabilityRead, 'read');
  assert.equal(report.liveHardwareVerified, false);
  assert.equal(report.status, 'unverified_hardware');
  assert.deepEqual(calls, [{ file: '/usr/bin/tpm2_getcap', args: ['properties-fixed', '-T', 'device:/dev/tpmrm0'] }]);
  assert.doesNotMatch(JSON.stringify(report), /PRIVATE|VENDOR_STRING/);
});

test('TPM tool failures or non-TPM2 output cannot establish device-and-tool readiness', async (t) => {
  for (const result of [{ status: 'timeout', stdout: 'PRIVATE' }, ok('not a TPM capability report'), { status: 'spawn_error', stdout: '' }]) {
    await t.test(result.status + (result.stdout ? '-output' : ''), async () => {
      const report = await probeHardwareSecurity({
        platform: 'linux', fsApi: fakeFs({ characters: ['/dev/tpm0'], files: ['/usr/bin/tpm2_getcap'] }), runner: async () => result,
      });
      assert.equal(report.tpm.readiness, 'device_detected');
      assert.equal(report.liveHardwareVerified, false);
      assert.doesNotMatch(JSON.stringify(report), /PRIVATE/);
    });
  }
});

test('a remote Linux host cannot pretend to probe a device plugged into a Mac', async () => {
  const report = await probeHardwareSecurity({
    platform: 'linux', expectedPlatform: 'macos',
    fsApi: { async stat() { throw new Error('must not inspect this host'); } },
    runner: async () => { throw new Error('must not run tools on this host'); },
  });
  assert.equal(report.execution.matchesExpectedPlatform, false);
  assert.equal(report.host.platform, 'linux');
  assert.equal(report.status, 'missing_hardware');
  assert.equal(report.liveHardwareVerified, false);
  assert.match(report.remediation.join(' '), /computer where the device is connected/);
});

test('unsupported hosts are reported without tool installation or invocation', async () => {
  const report = await probeHardwareSecurity({ platform: 'win32', fsApi: fakeFs(), runner: async () => { throw new Error('must not run'); } });
  assert.equal(report.host.platform, 'unsupported');
  assert.equal(report.liveHardwareVerified, false);
  assert.equal(report.status, 'missing_hardware');
});

test('bounded process runner terminates excessive stdout or stderr without retaining stderr', async (t) => {
  for (const stream of ['stdout', 'stderr']) {
    await t.test(stream, async () => {
      const result = await runBoundedCommand(process.execPath, ['-e', `require('node:fs').writeSync(${stream === 'stdout' ? 1 : 2}, 'x'.repeat(4096))`], { maxOutputBytes: 128, timeoutMs: 2000 });
      assert.equal(result.status, 'output_limit');
      assert.equal(result.stdout, '');
      assert.equal('stderr' in result, false);
    });
  }
});

test('bounded process runner terminates a stalled child and does not inherit credential environment', async () => {
  const stalled = await runBoundedCommand(process.execPath, ['-e', 'setInterval(() => {}, 1000)'], { timeoutMs: 100 });
  assert.equal(stalled.status, 'timeout');
  const variable = 'DUNESUB_PROBE_TEST_PRIVATE_TOKEN';
  process.env[variable] = 'test-only-private-value';
  try {
    const result = await runBoundedCommand(process.execPath, ['-e', `require('node:fs').writeSync(1, process.env.${variable} === undefined ? 'absent' : 'inherited')`]);
    assert.equal(result.status, 'ok');
    assert.equal(result.stdout.trim(), 'absent');
  } finally { delete process.env[variable]; }
});
