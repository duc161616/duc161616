export const mentionKinds = [
  { kind: "finding", label: "Finding", alias: "finding", zh: "漏洞" },
  { kind: "asset", label: "Asset", alias: "asset", zh: "资产" },
  { kind: "company", label: "Company", alias: "company", zh: "企业" },
  { kind: "endpoint", label: "Endpoint", alias: "api", zh: "接口" },
  { kind: "ip", label: "IP", alias: "ip", zh: "IP" },
  { kind: "app", label: "App", alias: "app", zh: "应用" },
  { kind: "root_domain", label: "Domain", alias: "domain", zh: "域名" },
  { kind: "subdomain", label: "Subdomain", alias: "subdomain", zh: "子域名" },
  { kind: "service", label: "Service", alias: "service", zh: "服务" },
] as const;

export type MentionKind = (typeof mentionKinds)[number]["kind"];
export interface ChatMention {
  kind: MentionKind;
  id: number;
  label: string;
  description: string;
}

export function activeMention(value: string, caret: number) {
  const before = value.slice(0, caret);
  const start = before.lastIndexOf("@");
  if (start < 0 || (start > 0 && /[\w.+/-]/.test(before[start - 1]))) return null;
  const query = before.slice(start + 1);
  if (/[[\]\r\n@]/.test(query) || query.length > 220) return null;
  return { start, end: caret, query };
}

export function mentionSearch(query: string) {
  const text = query.trimStart().toLowerCase();
  for (const item of mentionKinds) {
    for (const alias of [item.label.toLowerCase(), item.alias, item.zh.toLowerCase()]) {
      if (text === alias || text.startsWith(`${alias} `) || (/[^a-z]/.test(alias) && text.startsWith(alias))) {
        return { kind: item.kind, query: query.trimStart().slice(alias.length).trim(), categories: [] };
      }
    }
  }
  const categories = mentionKinds.filter(
    (item) =>
      item.label.toLowerCase().startsWith(text) || item.alias.startsWith(text) || item.zh.toLowerCase().startsWith(text),
  );
  return { kind: "" as const, query: query.trim(), categories };
}

export function mentionToken(item: ChatMention) {
  const kind = mentionKinds.find((entry) => entry.kind === item.kind)?.label ?? "Asset";
  const label = item.label
    .replace(/[[\]]/g, (char) => (char === "[" ? "（" : "）"))
    .replace(/\s+/g, " ")
    .slice(0, 100);
  return `@[${kind}#${item.id} ${label}]`;
}

// Tokens carry the English label; the Chinese labels are still accepted so drafts
// and history written before the translation keep resolving. Must stay in sync
// with chatMentionPattern in server/chat_mentions.go.
const mentionTokenPattern = new RegExp(
  `@\\[(${mentionKinds.flatMap((item) => [item.label, item.zh]).join("|")})#([0-9]+)(?: ([^\\]\\r\\n]*))?\\]`,
  "g",
);

export function selectedMentions(value: string) {
  return [...value.matchAll(mentionTokenPattern)].map(
    (match) => ({
      token: match[0],
      label: `${match[1]} #${match[2]}${match[3] ? ` · ${match[3]}` : ""}`,
      start: match.index,
    }),
  );
}
