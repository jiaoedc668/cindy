/** Dev-only native assets. Compile on explicit setup, never while polling settings.
 * Generated executables stay in userData; UAC setup copies the privileged pair
 * into the protected service directory without changing checkout permissions.
 */
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { promisify } from 'node:util';
import type { WindowsDesktopSetupPhase } from '../../shared/remoteDesktop';
import { createLogger } from '../logger';

const exec = promisify(execFile);
const log = createLogger('windows-desktop-setup');
export interface WindowsDesktopAssets {
  binary: string;
  addon: string;
}

function cacheRoot(userData: string): string {
  return path.join(userData, 'remote-desktop', 'windows-development');
}

async function latestInstalledAssets(userData: string): Promise<WindowsDesktopAssets | null> {
  const root = cacheRoot(userData);
  let entries: string[];
  try {
    entries = await fs.readdir(root);
  } catch {
    return null;
  }
  let latest: { binary: string; addon: string; mtime: number } | null = null;
  for (const name of entries) {
    const directory = path.join(root, name);
    const binary = path.join(directory, 'cindy-windows-desktop-host.exe');
    const addon = path.join(directory, 'cindy-windows-desktop-host.node');
    const input = path.join(directory, 'cindy-windows-desktop-input.exe');
    const receipt = path.join(directory, 'ready');
    try {
      await Promise.all([
        fs.access(binary),
        fs.access(addon),
        fs.access(input),
        fs.access(receipt),
      ]);
      const mtime = (await fs.stat(receipt)).mtimeMs;
      if (!latest || mtime > latest.mtime) latest = { binary, addon, mtime };
    } catch {
      /* Incomplete cache entries are not an installed helper. */
    }
  }
  return latest ? { binary: latest.binary, addon: latest.addon } : null;
}
interface DevelopmentRuntime {
  application: string;
  executable: string;
  userData: string;
  arch: string;
  run?: (args: string[], env: NodeJS.ProcessEnv) => Promise<unknown>;
}

export function createWindowsDevelopmentAssets(runtime: DevelopmentRuntime) {
  let describing: Promise<{
    application: string;
    executable: string;
    source: string;
    directory: string;
    fingerprint: string;
  }> | null = null;
  let building: Promise<WindowsDesktopAssets> | null = null;
  let buildingFingerprint: string | null = null;
  const describe = () => {
    if (describing) return describing;
    describing = (async () => {
      if (runtime.arch !== 'x64' && runtime.arch !== 'arm64')
        throw new Error('DESKTOP_NATIVE_BUILD_FAILED');
      const application = await fs.realpath(runtime.application);
      const executable = await fs.realpath(runtime.executable);
      const source = path.join(application, 'native', 'remote-desktop');
      const hash = createHash('sha256')
        .update('windows-development-service-v1')
        .update(application)
        .update(executable)
        .update(runtime.arch);
      for (const crate of ['windows-host', 'windows-input']) {
        const root = path.join(source, crate);
        const files = [
          'Cargo.toml',
          'Cargo.lock',
          ...(crate === 'windows-host' ? ['build.rs'] : []),
        ];
        for (const name of (await fs.readdir(path.join(root, 'src'))).sort()) {
          if (name.endsWith('.rs')) files.push(path.join('src', name));
        }
        for (const file of files)
          hash
            .update(crate)
            .update(file)
            .update(await fs.readFile(path.join(root, file)));
      }
      const fingerprint = hash.digest('hex');
      return {
        application,
        executable,
        source,
        fingerprint,
        directory: path.join(cacheRoot(runtime.userData), fingerprint),
      };
    })().finally(() => {
      describing = null;
    });
    return describing;
  };
  const assets = (directory: string): WindowsDesktopAssets => ({
    binary: path.join(directory, 'cindy-windows-desktop-host.exe'),
    addon: path.join(directory, 'cindy-windows-desktop-host.node'),
  });
  const run =
    runtime.run ??
    (async (args, env) => {
      await exec('cargo', args, {
        env: { ...process.env, ...env },
        windowsHide: true,
        timeout: 300_000,
        maxBuffer: 1024 * 1024,
      });
    });

  async function resolve(
    prepare = false,
    progress?: (phase: WindowsDesktopSetupPhase) => void,
  ): Promise<WindowsDesktopAssets | null> {
    const value = await describe();
    const result = assets(value.directory);
    const input = path.join(value.directory, 'cindy-windows-desktop-input.exe');
    const receipt = path.join(value.directory, 'ready');
    try {
      await Promise.all([fs.access(result.binary), fs.access(result.addon), fs.access(input)]);
      if ((await fs.readFile(receipt, 'utf8')) === value.fingerprint) return result;
    } catch {
      /* Explicit setup prepares missing or partial assets. */
    }
    if (!prepare) return null;
    if (building && buildingFingerprint === value.fingerprint) return building;
    const fingerprint = value.fingerprint;
    buildingFingerprint = fingerprint;
    building = (async () => {
      await fs.mkdir(value.directory, { recursive: true });
      const target =
        runtime.arch === 'arm64' ? 'aarch64-pc-windows-msvc' : 'x86_64-pc-windows-msvc';
      // Rust/linker intermediate paths can exceed Windows MAX_PATH below a
      // long named profile plus the fingerprint. Keep only finished assets there.
      const buildDirectory = await fs.mkdtemp(path.join(os.tmpdir(), 'cindy-wd-'));
      const output = path.join(buildDirectory, target, 'release');
      const env = {
        CINDY_DESKTOP_DEV_APP: value.application,
        CINDY_DESKTOP_DEV_EXECUTABLE: value.executable,
      };
      const args = [
        'build',
        '--release',
        '--locked',
        '--target',
        target,
        '--target-dir',
        buildDirectory,
      ];
      let stage = 'compilingHost';
      try {
        progress?.('compilingHost');
        await run(
          [
            ...args,
            '--manifest-path',
            path.join(value.source, 'windows-host', 'Cargo.toml'),
            '--features',
            'development',
          ],
          env,
        );
        stage = 'compilingInput';
        progress?.('compilingInput');
        await run(
          [...args, '--manifest-path', path.join(value.source, 'windows-input', 'Cargo.toml')],
          env,
        );
        stage = 'publishing';
        await fs.copyFile(path.join(output, 'cindy-windows-desktop-host.exe'), result.binary);
        await fs.copyFile(path.join(output, 'cindy_windows_desktop_host.dll'), result.addon);
        await fs.copyFile(path.join(output, 'cindy-windows-desktop-input.exe'), input);
        await fs.writeFile(receipt, value.fingerprint);
        return result;
      } catch (error) {
        // Do not log cargo's argv, paths, output or inherited environment. These
        // fixed diagnostics distinguish missing tools, compile errors and I/O.
        const details = error as { code?: unknown; killed?: unknown; stderr?: unknown };
        const code =
          typeof details?.code === 'number'
            ? details.code
            : typeof details?.code === 'string' && /^[A-Z_]{1,40}$/.test(details.code)
              ? details.code
              : 'UNKNOWN';
        const compiler =
          typeof details?.stderr === 'string'
            ? details.stderr.match(/error\[(E[0-9]{4})\]/)?.[1]
            : undefined;
        log.warn('component preparation failed', {
          stage,
          code,
          timeout: details?.killed === true,
          compiler,
        });
        await fs.rm(receipt, { force: true }).catch(() => {});
        throw new Error('DESKTOP_NATIVE_BUILD_FAILED');
      } finally {
        await fs
          .rm(buildDirectory, { recursive: true, force: true, maxRetries: 3, retryDelay: 50 })
          .catch(() => {});
      }
    })().finally(() => {
      if (buildingFingerprint === fingerprint) {
        building = null;
        buildingFingerprint = null;
      }
    });
    return building;
  }
  return { resolve, installed: () => latestInstalledAssets(runtime.userData) };
}
