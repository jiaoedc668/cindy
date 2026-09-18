import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type {
  DesktopLocalState,
  WindowsDesktopSetupPhase,
  WindowsDesktopSetupState,
  WindowsDesktopSupport,
  WindowsAutoUnlockState,
} from '../../../shared/remoteDesktop';
import { Button } from '@/components/ui/button';
import { Switch } from '@/components/ui/switch';
import { RemoteDesktopPermissions } from './RemoteDesktopPermissions';
import { extractIpcError } from '@/utils/ipcError';

const phaseCopy: Record<WindowsDesktopSetupPhase, string> = {
  preparing: 'remoteDesktop.windowsPreparing',
  compilingHost: 'remoteDesktop.windowsCompilingHost',
  compilingInput: 'remoteDesktop.windowsCompilingInput',
  compilingUnlock: 'remoteDesktop.windowsCompilingUnlock',
  authorizing: 'remoteDesktop.windowsAuthorizing',
  verifying: 'remoteDesktop.windowsVerifying',
  removing: 'remoteDesktop.windowsRemoving',
};

export function RemoteDesktopSetting() {
  const { t, i18n } = useTranslation();
  const [autoUnlock, setAutoUnlock] = useState<WindowsAutoUnlockState>();
  const [unlockPending, setUnlockPending] = useState(false);
  const [unlockError, setUnlockError] = useState(false);
  const unlockChanging = useRef(false);
  const [windowsSupport, setWindowsSupport] = useState<WindowsDesktopSupport>();
  const [serviceError, setServiceError] = useState<'prepare' | 'setup' | null>(null);
  const [windowsDevelopment, setWindowsDevelopment] = useState(false);
  const [enabled, setEnabled] = useState(false);
  const [busy, setBusy] = useState(false);
  const [setupPending, setSetupPending] = useState(false);
  const [setup, setSetup] = useState<WindowsDesktopSetupState>();
  const [error, setError] = useState(false);
  const revision = useRef(0);
  const changing = useRef(false);
  const mounted = useRef(false);
  const setupRevision = useRef(-1);
  const applyState = useCallback((state: DesktopLocalState) => {
    if (!mounted.current) return;
    setEnabled(state.enabled);
    setWindowsSupport(state.windowsSupport);
    if (state.windowsAutoUnlock) setAutoUnlock(state.windowsAutoUnlock);
    setWindowsDevelopment(state.windowsDevelopment === true);
    if (state.windowsSetup && state.windowsSetup.revision >= setupRevision.current) {
      setupRevision.current = state.windowsSetup.revision;
      setSetup(state.windowsSetup);
      setServiceError(state.windowsSetup.error);
    }
  }, []);
  useEffect(() => {
    mounted.current = true;
    const api = window.electronAPI?.remoteDesktop;
    if (!api) return;
    let active = true;
    let reading = false;
    const refresh = () => {
      if (reading || changing.current) return;
      reading = true;
      const current = revision.current;
      void api
        .state(true)
        .then((state) => {
          if (active && current === revision.current) {
            applyState(state);
          }
        })
        .catch(() => {
          if (active) setError(true);
        })
        .finally(() => {
          reading = false;
        });
    };
    refresh();
    const timer = setInterval(refresh, 2000);
    return () => {
      mounted.current = false;
      active = false;
      clearInterval(timer);
    };
  }, [applyState]);
  if (!window.electronAPI?.remoteDesktop) return null;
  const setupBusy = setupPending || !!setup?.phase;
  const setupPhase = setup?.phase ?? (setupPending ? 'preparing' : null);
  return (
    <section
      aria-label={t('remoteDesktop.allow')}
      className="flex flex-col gap-3 rounded-lg bg-[var(--settings-input-bg)] p-3"
    >
      <div className="flex items-center justify-between gap-4">
        <div className="flex flex-col gap-1">
          <p className="text-13 font-medium text-[var(--text-primary)]">
            {t('remoteDesktop.allow')}
          </p>
          <p className="text-12 text-[var(--text-tertiary)]">{t('remoteDesktop.allowHint')}</p>
          {error && (
            <p role="alert" className="text-12 text-[var(--text-primary)]">
              {t('remoteDesktop.permissionHint')}
            </p>
          )}
        </div>
        <Switch
          aria-label={t('remoteDesktop.allow')}
          disabled={busy || setupBusy}
          checked={enabled}
          onCheckedChange={(next) => {
            revision.current++;
            changing.current = true;
            setBusy(true);
            setError(false);
            void window.electronAPI.remoteDesktop
              .enable(next)
              .then(() => setEnabled(next))
              .catch(() => setError(true))
              .finally(() => {
                changing.current = false;
                setBusy(false);
              });
          }}
        />
      </div>
      {enabled && windowsSupport && (
        <div className="flex items-center justify-between gap-4 border-t border-[var(--border-default)] pt-3">
          <div className="flex flex-col gap-1">
            <p className="text-13 font-medium text-[var(--text-primary)]">
              {t('remoteDesktop.windowsTitle')}
            </p>
            <p className="text-12 text-[var(--text-tertiary)]">
              {t(
                setupPhase
                  ? phaseCopy[setupPhase]
                  : windowsDevelopment && windowsSupport === 'missing'
                    ? 'remoteDesktop.windowsDevelopmentMissing'
                    : `remoteDesktop.windows${windowsSupport}`,
              )}
            </p>
            {windowsDevelopment && (
              <p className="text-12 text-[var(--text-tertiary)]">
                {t('remoteDesktop.windowsDevelopmentHint')}
              </p>
            )}
            {serviceError && !setupBusy && (
              <p role="alert" className="text-12 text-[var(--text-primary)]">
                {t(
                  serviceError === 'prepare'
                    ? 'remoteDesktop.windowsPreparationError'
                    : 'remoteDesktop.windowsError',
                )}
              </p>
            )}
          </div>
          <Button
            disabled={
              busy ||
              setupBusy ||
              unlockPending ||
              autoUnlock?.busy ||
              windowsSupport === 'installRequired'
            }
            onClick={() => {
              revision.current++;
              // Setup outlives this settings page. Keep polling its Main-owned
              // phase so leaving/reopening never hides a compiler or UAC wait.
              setSetupPending(true);
              setServiceError(null);
              void window.electronAPI.remoteDesktop
                .windowsSupport(windowsSupport !== 'ready')
                .then(() => window.electronAPI.remoteDesktop.state(true))
                .then(applyState)
                .catch((error) => {
                  if (mounted.current)
                    setServiceError(
                      extractIpcError(error)?.code === 'PRECONDITION_FAILED' ? 'prepare' : 'setup',
                    );
                })
                .finally(() => {
                  if (mounted.current) {
                    setSetupPending(false);
                    void window.electronAPI.remoteDesktop
                      .state(true)
                      .then(applyState)
                      .catch(() => {});
                  }
                });
            }}
          >
            {t(
              setupBusy
                ? 'remoteDesktop.windowsSettingUp'
                : windowsSupport === 'ready'
                  ? 'remoteDesktop.windowsDisable'
                  : windowsSupport === 'unavailable' || serviceError
                    ? 'remoteDesktop.windowsRetry'
                    : windowsSupport === 'updateRequired'
                      ? 'remoteDesktop.windowsUpdate'
                      : 'remoteDesktop.windowsEnable',
            )}
          </Button>
        </div>
      )}
      {enabled && windowsSupport && autoUnlock && (
        <div className="flex items-center justify-between gap-4 border-t border-[var(--border-default)] pt-3">
          <div className="flex flex-col gap-1">
            <p className="text-13 font-medium text-[var(--text-primary)]">
              {t('remoteDesktop.windowsAutoUnlockTitle')}
            </p>
            <p className="text-12 text-[var(--text-tertiary)]">
              {t('remoteDesktop.windowsAutoUnlockHint')}
            </p>
            <p className="text-12 text-[var(--text-tertiary)]">
              {t('remoteDesktop.windowsAutoUnlockStorage')}
            </p>
            {(unlockError || autoUnlock.error) && (
              <p role="alert" className="text-12 text-[var(--text-primary)]">
                {t(
                  autoUnlock.error === 'unlock'
                    ? 'remoteDesktop.windowsAutoUnlockFailed'
                    : 'remoteDesktop.windowsAutoUnlockSetupFailed',
                )}
              </p>
            )}
          </div>
          <Button
            loading={unlockPending || autoUnlock.busy}
            disabled={
              setupBusy ||
              (!autoUnlock.enabled && (windowsSupport !== 'ready' || !autoUnlock.available))
            }
            onClick={() => {
              if (unlockChanging.current) return;
              unlockChanging.current = true;
              setUnlockPending(true);
              setUnlockError(false);
              const locale = ['zh-CN', 'zh-TW', 'en', 'ja', 'ko'].includes(i18n.language)
                ? i18n.language
                : 'en';
              void window.electronAPI.remoteDesktop
                .windowsAutoUnlock(!autoUnlock.enabled, locale)
                .then(() => window.electronAPI.remoteDesktop.state(true))
                .then(applyState)
                .catch(() => {
                  if (mounted.current) setUnlockError(true);
                })
                .finally(() => {
                  unlockChanging.current = false;
                  if (mounted.current) setUnlockPending(false);
                });
            }}
          >
            {t(
              autoUnlock.enabled
                ? 'remoteDesktop.windowsAutoUnlockClear'
                : 'remoteDesktop.windowsAutoUnlockSetup',
            )}
          </Button>
        </div>
      )}
      {enabled && !windowsSupport && <RemoteDesktopPermissions />}
    </section>
  );
}
