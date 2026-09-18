import { app } from 'electron';
import { REMOTE_DESKTOP_OFFER_BUDGET } from '@cindy/device-link';
import { execFile } from 'node:child_process';
import { createRequire } from 'node:module';
import path from 'node:path';
import { promisify } from 'node:util';
import type { WindowsDesktopSupport, WindowsDesktopSetupPhase } from '../../shared/remoteDesktop';
import { createWindowsDevelopmentAssets, type WindowsDesktopAssets } from './windowsDevelopment';

const exec = promisify(execFile);
const requireNative = createRequire(import.meta.url);
let development: ReturnType<typeof createWindowsDevelopmentAssets> | null = null;
function developmentAssets() {
  return (development ??= createWindowsDevelopmentAssets({
    application: app.getAppPath(),
    executable: process.execPath,
    userData: app.getPath('userData'),
    arch: process.arch,
  }));
}
async function assets(
  prepare = false,
  progress?: (phase: WindowsDesktopSetupPhase) => void,
): Promise<WindowsDesktopAssets | null> {
  if (app.isPackaged)
    return {
      binary: path.join(
        process.resourcesPath,
        'tools',
        'remote-desktop',
        'cindy-windows-desktop-host.exe',
      ),
      addon: path.join(
        process.resourcesPath,
        'tools',
        'remote-desktop',
        'cindy-windows-desktop-host.node',
      ),
    };
  return progress
    ? developmentAssets().resolve(prepare, progress)
    : developmentAssets().resolve(prepare);
}
async function helper(
  prepare = false,
  progress?: (phase: WindowsDesktopSetupPhase) => void,
): Promise<WindowsDesktopAssets | null> {
  const current = await assets(prepare, progress);
  if (current || app.isPackaged) return current;
  return developmentAssets().installed();
}
export interface WindowsDesktopConnection {
  request(line: string): Promise<string>;
  close(): void;
}
export interface WindowsUnlockNative {
  windowsUnlockEnabled(binary: string, scope: string): boolean;
  configureWindowsUnlock(
    binary: string,
    scope: string,
    enabled: boolean,
    locale: string,
  ): Promise<boolean>;
  unlockWindows(binary: string, scope: string): Promise<boolean>;
  cancelWindowsUnlock(): void;
}
export async function loadWindowsUnlockNative(): Promise<{
  native: WindowsUnlockNative;
  binary: string;
} | null> {
  if (process.platform !== 'win32') return null;
  // Clearing a saved credential must not depend on rebuilding current Dev code.
  const prepared = await helper();
  if (!prepared) return null;
  const native = requireNative(prepared.addon) as Partial<WindowsUnlockNative>;
  if (
    typeof native.configureWindowsUnlock !== 'function' ||
    typeof native.windowsUnlockEnabled !== 'function' ||
    typeof native.unlockWindows !== 'function' ||
    typeof native.cancelWindowsUnlock !== 'function'
  )
    return null;
  return { native: native as WindowsUnlockNative, binary: prepared.binary };
}
export async function readWindowsDesktopSupport(): Promise<WindowsDesktopSupport | undefined> {
  if (process.platform !== 'win32') return undefined;
  try {
    const native = await helper();
    if (!native) return 'missing';
    const { stdout } = await exec(native.binary, ['--status'], {
      timeout: REMOTE_DESKTOP_OFFER_BUDGET.platformStatusMs,
      maxBuffer: 1024,
      windowsHide: true,
    });
    const status = stdout.trim();
    if (status === 'ready') {
      try {
        const connection = await openWindowsDesktopConnection({ mode: 'probe' });
        connection.close();
      } catch {
        return 'missing';
      }
    }
    return status === 'ready' ||
      status === 'missing' ||
      status === 'installRequired' ||
      status === 'updateRequired'
      ? status
      : 'unavailable';
  } catch {
    return 'unavailable';
  }
}
export async function configureWindowsDesktopSupport(
  enabled: boolean,
  progress?: (phase: WindowsDesktopSetupPhase) => void,
): Promise<void> {
  if (process.platform !== 'win32') throw new Error('DESKTOP_SYSTEM_SERVICE_UNAVAILABLE');
  let native: WindowsDesktopAssets | null;
  try {
    // Uninstall must use the last installed helper. Rebuilding current source
    // is not required to revoke an auto-start SYSTEM service.
    native = await helper(enabled, progress);
  } catch (error) {
    if (!enabled) {
      native = app.isPackaged ? null : await developmentAssets().installed();
      if (!native) throw error;
    } else if (!app.isPackaged) {
      throw new Error('DESKTOP_NATIVE_BUILD_FAILED');
    } else {
      throw error;
    }
  }
  if (!native) throw new Error('DESKTOP_SYSTEM_SERVICE_UNAVAILABLE');
  // Recreating a Dev cache does not revoke the installed grant.
  if (enabled && !app.isPackaged && (await readWindowsDesktopSupport()) === 'ready') return;
  progress?.('authorizing');
  await exec(
    native.binary,
    enabled ? ['--elevate-install', String(process.pid)] : ['--elevate-uninstall'],
    { timeout: 130_000, maxBuffer: 1024, windowsHide: true },
  );
  progress?.('verifying');
  if (enabled && (await readWindowsDesktopSupport()) !== 'ready')
    throw new Error('DESKTOP_SYSTEM_SERVICE_UNAVAILABLE');
}
export async function openWindowsDesktopConnection(
  init:
    | { mode: 'input' | 'probe' }
    | { mode: 'capture'; rect: number[]; cursorOverlay?: boolean; bitrate?: number },
): Promise<WindowsDesktopConnection> {
  if (process.platform !== 'win32') throw new Error('DESKTOP_SYSTEM_SERVICE_UNAVAILABLE');
  const prepared = await assets();
  if (!prepared) throw new Error('DESKTOP_SYSTEM_SERVICE_UNAVAILABLE');
  // Fixed native addon (checkout-bound in Dev), loaded only by Main. It opens the pipe in
  // this process and authenticates SCM/SYSTEM identity before sending anything.
  const native = requireNative(prepared.addon) as {
    DesktopConnection: { open(binary: string, init: string): Promise<WindowsDesktopConnection> };
  };
  return native.DesktopConnection.open(prepared.binary, JSON.stringify(init));
}
