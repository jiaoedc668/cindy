import type { WindowsUnlockNative } from './windowsHost';
import type { WindowsAutoUnlockState } from '../../shared/remoteDesktop';

/** Native credentials remain local; Main owns cancellation across account, lease
 * and settings changes, without returning a credential to any renderer. */
export class WindowsAutoUnlock {
  private generation = 0;
  private native: WindowsUnlockNative | null = null;
  private configuring = false;
  private error: WindowsAutoUnlockState['error'] = null;
  constructor(
    private readonly deps: {
      scope(): string | null;
      load(): Promise<{ native: WindowsUnlockNative; binary: string } | null>;
    },
  ) {}
  cancel(): void {
    this.generation++;
    this.native?.cancelWindowsUnlock();
  }
  async read(): Promise<WindowsAutoUnlockState> {
    const scope = this.deps.scope();
    try {
      const loaded = scope ? await this.deps.load() : null;
      if (loaded && scope === this.deps.scope()) {
        this.native = loaded.native;
        return {
          enabled: loaded.native.windowsUnlockEnabled(loaded.binary, scope!),
          available: true,
          busy: this.configuring,
          error: this.error,
        };
      }
    } catch {
      /* Native components or the credential vault are unavailable. */
    }
    return { enabled: false, available: false, busy: this.configuring, error: this.error };
  }
  async configure(enabled: boolean, locale: string): Promise<void> {
    if (this.configuring) throw new Error('DESKTOP_SETUP_BUSY');
    this.cancel();
    const generation = this.generation;
    const scope = this.deps.scope();
    this.configuring = true;
    this.error = null;
    try {
      const loaded = scope ? await this.deps.load() : null;
      if (!loaded || !scope || scope !== this.deps.scope())
        throw new Error('DESKTOP_AUTO_UNLOCK_FAILED');
      this.native = loaded.native;
      await loaded.native.configureWindowsUnlock(loaded.binary, scope, enabled, locale);
      if (generation !== this.generation || scope !== this.deps.scope()) {
        await loaded.native.configureWindowsUnlock(loaded.binary, scope, false, locale);
        throw new Error('DESKTOP_LEASE_EXPIRED');
      }
    } catch (error) {
      if (generation === this.generation) this.error = 'setup';
      throw error;
    } finally {
      this.configuring = false;
    }
  }
  async unlock(): Promise<void> {
    const scope = this.deps.scope();
    const generation = this.generation;
    if (!scope) return;
    try {
      const loaded = await this.deps.load();
      if (generation !== this.generation || scope !== this.deps.scope())
        throw new Error('DESKTOP_LEASE_EXPIRED');
      if (!loaded || !loaded.native.windowsUnlockEnabled(loaded.binary, scope)) return;
      this.native = loaded.native;
      await loaded.native.unlockWindows(loaded.binary, scope);
      this.error = null;
    } catch {
      if (generation === this.generation) this.error = 'unlock';
      // A failed optional unlock retains ordinary manual control.
    }
    if (generation !== this.generation || scope !== this.deps.scope())
      throw new Error('DESKTOP_LEASE_EXPIRED');
  }
}
