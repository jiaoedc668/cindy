import { describe, expect, it, vi } from 'vitest';
import { WindowsAutoUnlock } from '../windowsAutoUnlock';

function fixture() {
  let scope: string | null = 'account-a';
  let saved = false;
  const native = {
    windowsUnlockEnabled: vi.fn(() => saved),
    configureWindowsUnlock: vi.fn(
      async (_binary: string, _scope: string, value: boolean) => (saved = value),
    ),
    unlockWindows: vi.fn(async () => true),
    cancelWindowsUnlock: vi.fn(),
  };
  const load = vi.fn(async () => ({ native, binary: 'native-helper' }));
  const service = new WindowsAutoUnlock({ scope: () => scope, load });
  return { service, native, load, setScope: (value: string | null) => (scope = value) };
}
describe('Windows host-local automatic unlock', () => {
  it('does not prompt, save credentials or unlock while reading settings', async () => {
    const { service, native } = fixture();
    expect(await service.read()).toEqual({
      enabled: false,
      available: true,
      busy: false,
      error: null,
    });
    expect(native.configureWindowsUnlock).not.toHaveBeenCalled();
    expect(native.unlockWindows).not.toHaveBeenCalled();
  });
  it('requires explicit setup, forwards only scope and locale, and deletes on disable', async () => {
    const { service, native } = fixture();
    await service.unlock();
    expect(native.unlockWindows).not.toHaveBeenCalled();
    await service.configure(true, 'zh-CN');
    expect(native.configureWindowsUnlock).toHaveBeenCalledWith(
      'native-helper',
      'account-a',
      true,
      'zh-CN',
    );
    await service.unlock();
    expect(native.unlockWindows).toHaveBeenCalledWith('native-helper', 'account-a');
    await service.configure(false, 'en');
    expect((await service.read()).enabled).toBe(false);
  });
  it('cancels an in-flight unlock instead of starting input after a lease was revoked', async () => {
    const { service, native } = fixture();
    await service.configure(true, 'en');
    let finish!: (result: boolean) => void;
    native.unlockWindows.mockImplementation(() => new Promise((resolve) => (finish = resolve)));
    const unlocking = service.unlock();
    await Promise.resolve();
    service.cancel();
    finish(true);
    await expect(unlocking).rejects.toThrow('DESKTOP_LEASE_EXPIRED');
    expect(native.cancelWindowsUnlock).toHaveBeenCalled();
  });
  it('does not use a previous account credential after asynchronous asset loading', async () => {
    const { service, native, load, setScope } = fixture();
    await service.configure(true, 'en');
    load.mockImplementationOnce(async () => {
      setScope('account-b');
      return { native, binary: 'native-helper' };
    });
    await expect(service.unlock()).rejects.toThrow('DESKTOP_LEASE_EXPIRED');
    expect(native.unlockWindows).not.toHaveBeenCalled();
    setScope(null);
    expect((await service.read()).enabled).toBe(false);
  });
  it('removes a newly saved credential if the account changes during the native prompt', async () => {
    const { service, native, setScope } = fixture();
    native.configureWindowsUnlock.mockImplementationOnce(async () => {
      setScope('account-b');
      return true;
    });
    await expect(service.configure(true, 'en')).rejects.toThrow('DESKTOP_LEASE_EXPIRED');
    expect(native.configureWindowsUnlock).toHaveBeenLastCalledWith(
      'native-helper',
      'account-a',
      false,
      'en',
    );
  });
  it('retains manual control when optional unlock fails and never retries it internally', async () => {
    const { service, native } = fixture();
    await service.configure(true, 'en');
    native.unlockWindows.mockRejectedValue(new Error('native-failure'));
    await expect(service.unlock()).resolves.toBeUndefined();
    expect(native.unlockWindows).toHaveBeenCalledOnce();
    expect((await service.read()).error).toBe('unlock');
  });
});
