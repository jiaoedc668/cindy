import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createWindowsDevelopmentAssets } from '../windowsDevelopment';

let root: string;
let application: string;
let executable: string;
beforeAll(async () => {
  root = await fs.mkdtemp(path.join(os.tmpdir(), 'cindy-development-desktop-'));
  application = path.join(root, 'checkout', 'apps', 'desktop');
  executable = path.join(root, 'electron.exe');
  await fs.writeFile(executable, 'fake-runtime');
  for (const crate of ['windows-host', 'windows-input']) {
    const directory = path.join(application, 'native', 'remote-desktop', crate);
    await fs.mkdir(path.join(directory, 'src'), { recursive: true });
    await Promise.all(
      ['Cargo.toml', 'Cargo.lock', 'build.rs', path.join('src', 'main.rs')].map((name) =>
        fs.writeFile(path.join(directory, name), 'fake-native-source'),
      ),
    );
  }
});
afterAll(async () => {
  await fs.rm(root, { recursive: true, force: true });
});

function fixture(profile: string) {
  const run = vi.fn(async (args: string[], _env: NodeJS.ProcessEnv) => {
    const output = path.join(
      args[args.indexOf('--target-dir') + 1],
      args[args.indexOf('--target') + 1],
      'release',
    );
    await fs.mkdir(output, { recursive: true });
    const names = args.includes('development')
      ? ['cindy-windows-desktop-host.exe', 'cindy_windows_desktop_host.dll']
      : ['cindy-windows-desktop-input.exe'];
    await Promise.all(
      names.map((name) => fs.writeFile(path.join(output, name), 'fake-native-output')),
    );
  });
  const runtime = { application, executable, userData: path.join(root, profile), arch: 'x64', run };
  return { run, runtime, service: createWindowsDevelopmentAssets(runtime) };
}

describe('Dev Windows desktop components', () => {
  it('does not compile or prompt while settings poll, and coalesces explicit preparation', async () => {
    const { run, runtime, service } = fixture('first-setup');
    expect(await service.resolve()).toBeNull();
    expect(run).not.toHaveBeenCalled();
    const [first, second] = await Promise.all([service.resolve(true), service.resolve(true)]);
    expect(first).toEqual(second);
    expect(run).toHaveBeenCalledTimes(2);
    expect(run.mock.calls[0][0]).toContain('development');
    const buildArgs = run.mock.calls[0][0];
    const buildDirectory = buildArgs[buildArgs.indexOf('--target-dir') + 1];
    expect(path.relative(runtime.userData, buildDirectory).startsWith('..')).toBe(true);
    await expect(fs.access(buildDirectory)).rejects.toThrow();
    expect(run.mock.calls[0][1]).toEqual({
      CINDY_DESKTOP_DEV_APP: await fs.realpath(application),
      CINDY_DESKTOP_DEV_EXECUTABLE: await fs.realpath(executable),
    });
    expect(path.relative(runtime.userData, first!.binary).startsWith('..')).toBe(false);
    expect(await fs.readFile(executable, 'utf8')).toBe('fake-runtime');
    expect(await service.resolve()).toEqual(first);
    expect(run).toHaveBeenCalledTimes(2);
  });

  it('reuses prepared components after a Main restart without another build', async () => {
    const { run, runtime, service } = fixture('restart');
    const prepared = await service.resolve(true);
    run.mockClear();
    expect(await createWindowsDevelopmentAssets(runtime).resolve()).toEqual(prepared);
    expect(run).not.toHaveBeenCalled();
  });

  it('does not mark partial compilation ready and allows an explicit retry', async () => {
    const { run, service } = fixture('retry');
    run.mockRejectedValueOnce(new Error('compiler unavailable'));
    await expect(service.resolve(true)).rejects.toThrow('DESKTOP_NATIVE_BUILD_FAILED');
    expect(await service.resolve()).toBeNull();
    expect(await service.resolve(true)).not.toBeNull();
  });

  it('keeps loaded addon files separate when native source changes', async () => {
    const { runtime, service } = fixture('native-update');
    const previous = await service.resolve(true);
    const source = path.join(
      application,
      'native',
      'remote-desktop',
      'windows-host',
      'src',
      'main.rs',
    );
    const original = await fs.readFile(source);
    try {
      await fs.writeFile(source, 'updated-fake-native-source');
      const updated = createWindowsDevelopmentAssets(runtime);
      expect(await updated.resolve()).toBeNull();
      const current = await updated.resolve(true);
      expect(current!.addon).not.toBe(previous!.addon);
      expect(await fs.readFile(previous!.addon, 'utf8')).toBe('fake-native-output');
    } finally {
      await fs.writeFile(source, original);
    }
  });
});
