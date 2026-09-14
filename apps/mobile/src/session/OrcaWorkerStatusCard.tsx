import { useCallback, useEffect, useState } from 'react';
import { AppState, Pressable, ScrollView, StyleSheet, View } from 'react-native';
import { useFocusEffect } from 'expo-router';
import { ChevronDown, ChevronRight } from 'lucide-react-native';
import { Text } from '@/components/AppText';
import { useTheme, type ThemeColors } from '@/theme';
import { i18n } from '@/i18n';
import type { MobileMakerTransport } from '@/device-link/mobileMakerTransport';
import { fontWeight, iconSize, iconStroke, lineHeight, radius, typeScale } from '@/theme/tokens';

type Worker = { id?: string; label?: string; role?: string; status?: string; sessionId?: string };

const workerStatusKeys = new Set(['running', 'idle', 'done', 'error', 'archived']);

function statusLabel(status: string | undefined): string {
  const key = status && workerStatusKeys.has(status) ? status : 'unknown';
  return i18n.t(`session.presentation.collaboration.workerStatus.${key}`);
}

/**
 * 状态点语义色,对齐移动端既有约定(InteractionPanel:1907「已完成 statusReady /
 * 进行中 statusAccent / 其余 textTertiary」):statusAccent 专指运行/思考中,
 * idle、archived 与未知状态一律走中性色,不能和运行中撞色。
 */
function statusDotColor(status: string | undefined, colors: ThemeColors): string {
  if (status === 'error') return colors.statusError;
  if (status === 'done') return colors.statusDone;
  if (status === 'running') return colors.statusAccent;
  return colors.textTertiary;
}

const attentionStatuses = new Set(['done', 'error']);

function workerKey(worker: Worker, index: number): string {
  return worker.id ?? worker.sessionId ?? String(index);
}

function workersFrom(value: unknown): Worker[] {
  if (Array.isArray(value)) return value.filter((v): v is Worker => !!v && typeof v === 'object');
  if (value && typeof value === 'object' && Array.isArray((value as { workers?: unknown }).workers)) {
    return workersFrom((value as { workers: unknown }).workers);
  }
  return [];
}

export function OrcaWorkerStatusCard({ leadSessionId, maker, onOpenWorker }: {
  leadSessionId: string;
  maker: MobileMakerTransport;
  /** 打开该 Worker 的会话;只读口径由 collaboration.ts 按 orcaRole 判定。 */
  onOpenWorker?: (workerSessionId: string) => void;
}) {
  const { colors } = useTheme();
  const [workers, setWorkers] = useState<Worker[] | null>(null);
  // 对齐桌面右侧栏「协同」tab:默认不展开,靠 attention 点把用户拉回来。
  // 桌面关闭 tab ≡ 结束协同(disableOrca);手机版第一版只读,这里只是视图折叠。
  const [expanded, setExpanded] = useState(false);
  // 轮询门控与本屏既有写法同构([sessionId]:965-1010):focus 与 AppState 正交 ——
  // 推入文件浏览器等路由后本屏仍挂载(见 [sessionId]:3796-3798),不门控会在看不见
  // 的屏幕上持续发远端库读;后台时导航也可能仍是 focused,必须各自判定。
  const [focused, setFocused] = useState(false);
  const [appActive, setAppActive] = useState(AppState.currentState === 'active');
  useFocusEffect(useCallback(() => {
    setFocused(true);
    return () => setFocused(false);
  }, []));
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (next) => setAppActive(next === 'active'));
    return () => subscription.remove();
  }, []);
  // 换 Lead 等于换一份列表:清空快照与展开态。失焦/回前台不走这里,避免把已拿到的
  // 列表也一并清掉。
  // 已查看登记:workerKey → 查看时的状态。对齐桌面 useOrcaWorkerAttentionWatcher
  // 的边沿语义(enteredDone && !isViewed):记下「看的是哪个状态」,状态再变动时
  // 比对不上即重新提示;手机端只读、无法让 Worker 离开 done,不记已读点会永久亮着。
  const [acknowledged, setAcknowledged] = useState<Record<string, string>>({});
  useEffect(() => {
    setWorkers(null);
    setExpanded(false);
    setAcknowledged({});
  }, [leadSessionId]);
  const polling = focused && appActive;
  useEffect(() => {
    if (!polling) return;
    let active = true;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const load = async () => {
      try {
        const next = workersFrom(await maker.listOrcaWorkersByLead(leadSessionId));
        if (active) setWorkers(next);
      } catch {
        // 刷新失败保留上一份快照:弱网下的瞬时超时不应让整张卡消失。
      } finally {
        if (active) timer = setTimeout(() => void load(), 5000);
      }
    };
    void load();
    return () => {
      active = false;
      if (timer !== undefined) clearTimeout(timer);
    };
  }, [leadSessionId, maker, polling]);
  // 拿到非空快照前不占位:本卡在 sessionChrome 里,其 onLayout 高度是消息列表的
  // 顶部内距,先撑开再收起会让会话内容跳动。
  if (!workers?.length) return null;
  const title = i18n.t('session.presentation.collaboration.workersTitle', { n: workers.length });
  // 与桌面 useOrcaWorkerAttentionWatcher:44-49 一致:done 在被查看前同样算未读;
  // 查看过就不再提示,直到该 Worker 的状态再次变动。
  const pending = workers.filter((worker, index) =>
    attentionStatuses.has(worker.status ?? '')
    && acknowledged[workerKey(worker, index)] !== worker.status);
  const needsAttention = pending.length > 0;
  const attentionStatus = pending.some((worker) => worker.status === 'error') ? 'error' : 'done';
  const Chevron = expanded ? ChevronDown : ChevronRight;
  return <View style={[styles.card, { backgroundColor: colors.surface, borderColor: colors.border }]}>
    <Pressable
      accessibilityRole="button"
      accessibilityState={{ expanded }}
      accessibilityLabel={needsAttention ? `${title} · ${statusLabel(attentionStatus)}` : title}
      onPress={() => setExpanded((value) => !value)}
      style={styles.header}
      testID="session.orcaWorkers.toggle"
    >
      <Text style={[styles.title, { color: colors.textPrimary }]}>{title}</Text>
      {!expanded && needsAttention
        ? <View style={[styles.attentionDot, { backgroundColor: statusDotColor(attentionStatus, colors) }]} testID="session.orcaWorkers.attention" />
        : null}
      <Chevron accessible={false} color={colors.textTertiary} size={iconSize.md} strokeWidth={iconStroke.regular} />
    </Pressable>
    {/* 桌面 Worker 上限为 20(register.ts COLLABORATION_WORKER_LIMIT_MAX),按 44pt 行高
        展开后可达 880pt,会把消息视口挤没。这里限高滚动,卡片高度恒定可控。 */}
    {expanded ? <ScrollView style={styles.rows} nestedScrollEnabled>{workers.map((worker, index) => {
      const name = worker.label ?? worker.role ?? `Worker ${index + 1}`;
      const workerSessionId = worker.sessionId;
      const body = <>
        <View style={[styles.dot, { backgroundColor: statusDotColor(worker.status, colors) }]} />
        <Text numberOfLines={1} style={[styles.name, { color: colors.textPrimary }]}>{name}</Text>
        <Text style={[styles.status, { color: colors.textSecondary }]}>{statusLabel(worker.status)}</Text>
      </>;
      const key = workerKey(worker, index);
      // 没有 sessionId 的 Worker 无处可跳,保持静态行,不做假的可点外观。
      return onOpenWorker && workerSessionId
        ? <Pressable
            key={key}
            accessibilityRole="button"
            accessibilityLabel={`${name} · ${statusLabel(worker.status)}`}
            onPress={() => {
              // 打开即视为已查看:登记当前状态,清掉这一条的提示。
              setAcknowledged((prev) => ({ ...prev, [key]: worker.status ?? 'unknown' }));
              onOpenWorker(workerSessionId);
            }}
            style={({ pressed }) => [styles.row, styles.rowPressable, pressed && { opacity: 0.6 }]}
            testID={`session.orcaWorkers.worker.${workerSessionId}`}
          >
            {body}
            <ChevronRight accessible={false} color={colors.textTertiary} size={iconSize.sm} strokeWidth={iconStroke.regular} />
          </Pressable>
        : <View key={key} style={styles.row}>{body}</View>;
    })}</ScrollView> : null}
  </View>;
}

const styles = StyleSheet.create({ card: { marginHorizontal: 12, marginBottom: 8, padding: 10, borderWidth: StyleSheet.hairlineWidth, borderRadius: radius.container }, header: { flexDirection: 'row', alignItems: 'center', gap: 7, minHeight: 44 }, title: { flex: 1, fontSize: typeScale.body, fontWeight: fontWeight.semibold }, attentionDot: { width: 6, height: 6, borderRadius: radius.micro }, rows: { maxHeight: 264 }, row: { flexDirection: 'row', alignItems: 'center', gap: 7, minHeight: lineHeight.listBody }, rowPressable: { minHeight: 44 }, dot: { width: iconSize.sm, height: iconSize.sm, borderRadius: radius.micro }, name: { flex: 1, fontSize: typeScale.body }, status: { fontSize: typeScale.caption } });
