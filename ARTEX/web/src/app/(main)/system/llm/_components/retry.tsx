"use client";

// LLM 重试配置的共用件：五层重试各自的「次数 + 间隔」。
//
// 五层从内到外：建连(SDK) → 空响应(SDK) → 同 provider 安全窗口 → 轮询熔断 → 意图重跑。
// 前三层跟着端点走，所以每个模型配置都能覆盖全局默认；后两层是进程级的，只有全局一份。
//
// 所有输入都遵循同一套「留空 = 不配置」语义，与后端 db.RetryRule 一致：
//   次数   空/0 = 用内置默认 | -1 = 关闭这层重试 | >0 = 用这个次数
//   间隔   空/0 = 用这层原本的指数退避 | >0 = 改用这个固定毫秒间隔

import * as React from "react";

import { Loader2Icon, SaveIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { api } from "@/lib/api";
import type { LLMRetryOverride, LLMRetryPolicy, LLMRetryRule } from "@/lib/types";

export const ZERO_RULE: LLMRetryRule = { attempts: 0, interval_ms: 0 };
export const ZERO_OVERRIDE: LLMRetryOverride = {
  connect: ZERO_RULE,
  empty: ZERO_RULE,
  stream: ZERO_RULE,
};
const ZERO_POLICY: LLMRetryPolicy = {
  ...ZERO_OVERRIDE,
  breaker: ZERO_RULE,
  intent: ZERO_RULE,
};

type LayerMeta = {
  title: string;
  /** 这层重试发生在哪、由谁执行 */
  where: string;
  /** 什么样的错误会走到这层——具体到状态码，别让人猜 */
  trigger: string;
  /** 长得像但【不】走这层的错误，省得填了没反应还以为是 bug */
  skips?: string;
  desc: string;
  attemptsLabel: string;
  /** 次数留空时的默认值，用于占位符 */
  defAttempts: number;
  /** 间隔留空时的默认策略，用于占位符 */
  defInterval: string;
  /** 次数填 -1 的含义 */
  offHint: string;
};

export const RETRY_LAYERS = {
  connect: {
    title: "Connect retries",
    where: "SDK · before a 200 comes back",
    trigger:
      "Cannot connect, or no 200 yet: network-level errors such as connection reset, read/write timeout or DNS failure, plus HTTP 408, 429, 500, 502, 503, 504.",
    skips: "Every other status code (400 / 401 / 403 / 404 / 413 / 422 and so on) is a deterministic refusal; resending fails the same way, so it is raised directly.",
    desc: "Resend the same request as is. Once the stream has started (a 200 is in hand), a drop midway is no longer this layer's concern.",
    attemptsLabel: "Retries",
    defAttempts: 3,
    defInterval: "0.5s->1s->2s exponential (capped at 8s)",
    offHint: "-1 = never retry, raise the failure immediately",
  },
  empty: {
    title: "Empty-response retries",
    where: "SDK · openai format only",
    trigger:
      "HTTP 200 and finish_reason is a normal stop, yet the whole response contains no content block — gateway empty frames, dropped reasoning fields and sampling hiccups all look like this.",
    skips: "An empty result caused by max_tokens truncation does not count (that needs a higher output limit; resending only hits it again).",
    desc: "This resends the whole prompt, so it is expensive on long contexts; keep the count low.",
    attemptsLabel: "Retries",
    defAttempts: 2,
    defInterval: "0.5s->1s->2s exponential (capped at 8s)",
    offHint: "-1 = hand an empty response through as is",
  },
  stream: {
    title: "Retry within the provider's safe window",
    where: "This project · before output is delivered",
    trigger:
      "The problem comes only after the stream is established (a 200 is in hand): a mid-stream drop, provider overloaded, or a 429 / 5xx error event inside the stream — and not a single token has reached the caller yet.",
    skips:
      "None of these are retried: quota exhaustion (402 / insufficient_quota, handed to polling to switch profiles), context too long (413 / context length, handed to compaction), and deterministic 400 / 401 / 403 / 404 / 422 refusals.",
    desc: "Replay the same request on the same profile. Since no output has been delivered yet, a replay duplicates neither model output nor tool execution.",
    attemptsLabel: "Retries",
    defAttempts: 2,
    defInterval: "0.5s->1s exponential (capped at 4s)",
    offHint: "-1 = hand a dropped stream to the outer intent rerun",
  },
  breaker: {
    title: "Poll breaker",
    where: "This project · per process, one globally",
    trigger:
      "Trips when transient failures (429, 5xx, network errors) accumulate to the threshold; deterministic failures such as insufficient balance (402), invalid key (401 / 403) or model not found (404) ignore the threshold and trip on the first occurrence.",
    skips: "One success resets the count, so an occasionally flaky profile is never slowly accumulated into a trip.",
    desc: "After tripping, the profile cools down and polling skips it during the cooldown. The state is persisted and survives restarts.",
    attemptsLabel: "Failures before tripping",
    defAttempts: 3,
    defInterval: "1min->5min->30min steps",
    offHint: "-1 = transient failures never trip the breaker (deterministic failures still do)",
  },
  intent: {
    title: "Rerun intent",
    where: "This project · per process, one globally",
    trigger:
      "None of the earlier layers caught it: the worker ends with model_error — every inner retry is exhausted, or the stream dropped after it had started delivering output (replay is unsafe then, so only a full rerun works).",
    skips: "Quota exhaustion is handled by polling switching profiles, not rerun here; when the task is paused, killed or wrapping up, it yields at once without consuming backoff time.",
    desc: "Rerun the whole intent from the start. This is the outermost layer, so one rerun multiplies the counts of every layer inside it.",
    attemptsLabel: "Rerun count",
    defAttempts: 2,
    defInterval: "Fixed 3s",
    offHint: "-1 = no rerun; the intent is judged blocked at once",
  },
} satisfies Record<string, LayerMeta>;

type LayerKey = keyof typeof RETRY_LAYERS;

/** 毫秒的人话，只用于在输入框旁边回显，免得数零。 */
function humanMs(ms: number) {
  if (!Number.isFinite(ms) || ms <= 0) return "";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60_000) return `${Number((ms / 1000).toFixed(2))}s`;
  return `${Number((ms / 60_000).toFixed(2))}min`;
}

/** 受控数字输入：空串 ↔ 0，中间态（"-"、"1e"）原样留在本地，不打扰父级。 */
function NumField({
  id,
  value,
  onChange,
  placeholder,
  min,
}: {
  id: string;
  value: number;
  onChange: (n: number) => void;
  placeholder: string;
  min: number;
}) {
  const [text, setText] = React.useState(value === 0 ? "" : String(value));
  // 父级换了一整套值（读取到策略、切换配置）时跟上；自己敲字时不会走到这里，
  // 因为那时 value 已经等于本地文本 parse 后的结果。
  React.useEffect(() => {
    const incoming = value === 0 ? "" : String(value);
    setText((cur) => (Number(cur || 0) === value ? cur : incoming));
  }, [value]);
  return (
    <Input
      id={id}
      type="number"
      min={min}
      className="w-28 shrink-0"
      value={text}
      placeholder={placeholder}
      onChange={(e) => {
        setText(e.target.value);
        const n = Number(e.target.value);
        onChange(e.target.value.trim() === "" || !Number.isFinite(n) ? 0 : Math.trunc(n));
      }}
    />
  );
}

/** 一层重试的两个旋钮。idPrefix 用来在同一页出现多次时保住 label 的 htmlFor。 */
export function RetryRuleFields({
  layer,
  idPrefix,
  value,
  onChange,
  compact,
}: {
  layer: LayerKey;
  idPrefix: string;
  value: LLMRetryRule;
  onChange: (r: LLMRetryRule) => void;
  /** true = 配置抽屉里的紧凑版：省掉展开说明，只留「什么错误会走到这层」这一句 */
  compact?: boolean;
}) {
  const meta = RETRY_LAYERS[layer];
  const human = humanMs(value.interval_ms);
  return (
    <div className={compact ? "grid gap-2" : "grid gap-3 rounded-lg border p-3"}>
      <div className="grid gap-0.5">
        <div className="flex flex-wrap items-baseline gap-2">
          <Label className="text-sm">{meta.title}</Label>
          <span className="text-muted-foreground text-xs">{meta.where}</span>
        </div>
        {/* 哪些错误会走到这层，具体到状态码——填了旋钮却看不到效果，多半是错误压根不落在这层。 */}
        <p className="text-muted-foreground text-xs">
          <span className="font-medium text-foreground">触发</span>：{meta.trigger}
        </p>
        {!compact && meta.skips && (
          <p className="text-muted-foreground text-xs">
            <span className="font-medium text-foreground">不走这层</span>：{meta.skips}
          </p>
        )}
        {!compact && <p className="text-muted-foreground text-xs">{meta.desc}</p>}
      </div>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-n`} className="text-muted-foreground text-xs">
            {meta.attemptsLabel}
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-n`}
            min={-1}
            value={value.attempts}
            placeholder={`Default ${meta.defAttempts}`}
            onChange={(n) => onChange({ ...value, attempts: n })}
          />
        </div>
        <div className="flex items-center gap-2">
          <Label htmlFor={`${idPrefix}-${layer}-ms`} className="text-muted-foreground text-xs">
            间隔 ms
          </Label>
          <NumField
            id={`${idPrefix}-${layer}-ms`}
            min={0}
            value={value.interval_ms}
            placeholder="Default backoff"
            onChange={(n) => onChange({ ...value, interval_ms: n })}
          />
          <span className="text-muted-foreground text-xs">{human ? `Fixed ${human}` : meta.defInterval}</span>
        </div>
      </div>
      {!compact && <p className="text-muted-foreground text-xs">留空 = 用默认；{meta.offHint}。</p>}
    </div>
  );
}

/** 模型配置抽屉里的三层覆盖（跟着端点走的那三层）。 */
export function ProfileRetryFields({
  value,
  onChange,
}: {
  value: LLMRetryOverride;
  onChange: (o: LLMRetryOverride) => void;
}) {
  return (
    <div className="grid gap-3 rounded-lg border p-3">
      <div className="grid gap-0.5">
        <Label className="text-sm">重试覆盖</Label>
        <p className="text-muted-foreground text-xs">
          只对这个配置生效，覆盖「重试与退避」里的全局默认。每格留空 = 跟随全局；次数填 -1 = 关掉这层重试；
          间隔填了就用固定间隔取代指数退避。熔断与意图重跑是进程级的，只能在全局那页调。
        </p>
      </div>
      {(["connect", "empty", "stream"] as const).map((k) => (
        <div key={k} className="border-t pt-3 first:border-t-0 first:pt-0">
          <RetryRuleFields
            compact
            layer={k}
            idPrefix="pf"
            value={value[k]}
            onChange={(r) => onChange({ ...value, [k]: r })}
          />
        </div>
      ))}
    </div>
  );
}

/** 「重试与退避」tab：五层的全局默认值。 */
export function RetryPolicyPanel() {
  const [policy, setPolicy] = React.useState<LLMRetryPolicy>(ZERO_POLICY);
  const [loading, setLoading] = React.useState(true);
  const [saving, setSaving] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const p = await api.llmRetryPolicy();
      setPolicy({ ...ZERO_POLICY, ...p });
    } catch (e) {
      toast.error(`Failed to read the retry policy: ${(e as Error).message}`);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function save() {
    if (saving) return;
    setSaving(true);
    try {
      // 后端会把越界值夹回区间并回传，直接用回传值刷新，所见即所存。
      const saved = await api.saveLLMRetryPolicy(policy);
      setPolicy({ ...ZERO_POLICY, ...saved });
      toast.success("Saved and effective at once (the call already in flight keeps the old parameters)");
    } catch (e) {
      toast.error(`Save failed: ${(e as Error).message}`);
    } finally {
      setSaving(false);
    }
  }

  const set = (k: LayerKey) => (r: LLMRetryRule) => setPolicy((p) => ({ ...p, [k]: r }));

  if (loading) {
    return (
      <div className="flex items-center gap-2 rounded-lg border border-dashed p-10 text-muted-foreground text-sm">
        <Loader2Icon className="size-4 animate-spin" /> 读取重试策略…
      </div>
    );
  }

  return (
    <div className="grid gap-4">
      <div className="rounded-lg border bg-muted/30 p-3 text-muted-foreground text-xs leading-relaxed">
        一次模型调用的失败会依次经过五层重试，由内到外：
        <span className="text-foreground"> 建连 → 空响应 → 同 provider 安全窗口 → 轮询熔断 → 意图重跑</span>
        。内层用尽才轮到外层，所以次数是
        <span className="text-foreground">相乘</span>
        的——把每层都拉满，一次抖动能烧掉几十次请求。
        全部留空即当前默认值，与没有这页时的行为完全一致。前三层可以在每个模型配置里单独覆盖。
      </div>

      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
        {(Object.keys(RETRY_LAYERS) as LayerKey[]).map((k) => (
          <RetryRuleFields key={k} layer={k} idPrefix="gl" value={policy[k]} onChange={set(k)} />
        ))}
      </div>

      <div className="flex gap-2">
        <Button onClick={save} disabled={saving}>
          {saving ? <Loader2Icon className="animate-spin" /> : <SaveIcon />}
          保存
        </Button>
        <Button variant="outline" onClick={() => setPolicy(ZERO_POLICY)} disabled={saving}>
          全部恢复默认
        </Button>
      </div>
    </div>
  );
}
