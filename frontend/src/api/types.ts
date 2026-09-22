export type Config = 'runtime' | 'permanent'
export type Target = 'runtime' | 'permanent' | 'both'

export interface Status {
  version: string
  state: string
  default_zone: string
  panic_mode: boolean
  log_denied: string
  active_zones: Record<string, { interfaces: string[]; sources: string[] }>
}

export interface ZoneSummary {
  name: string
  runtime: boolean
  permanent: boolean
  default: boolean
  active: boolean
  interfaces: string[]
  sources: string[]
}

export interface PortSpec {
  port: string
  protocol: string
}

export interface ForwardPortSpec extends PortSpec {
  to_port: string
  to_addr: string
}

export interface Limit {
  value: string
  burst?: number
}

export type RuleElement =
  | { type: 'service'; name: string }
  | { type: 'port'; port: string; protocol: string }
  | { type: 'source-port'; port: string; protocol: string }
  | { type: 'protocol'; value: string }
  | { type: 'icmp-block'; name: string }
  | { type: 'icmp-type'; name: string }
  | { type: 'masquerade' }
  | { type: 'forward-port'; port: string; protocol: string; to_port: string; to_addr: string }
  | { type: 'tcp-mss-clamp'; value: string }

export type RuleLog =
  | { type: 'log'; prefix: string; level: string; limit: Limit | null }
  | { type: 'nflog'; group: number; prefix: string; threshold: number; limit: Limit | null }

export interface RuleAction {
  type: 'accept' | 'reject' | 'drop' | 'mark'
  reject_type: string
  set: string
  limit: Limit | null
}

export interface RichRule {
  family: '' | 'ipv4' | 'ipv6'
  priority: number
  source: { addr: string; mac: string; ipset: string; invert: boolean } | null
  destination: { addr: string; ipset: string; invert: boolean } | null
  element: RuleElement | null
  log: RuleLog | null
  audit: { limit: Limit | null } | null
  action: RuleAction | null
}

export interface ZoneView {
  short: string
  description: string
  target: string
  services: string[]
  ports: PortSpec[]
  protocols: string[]
  source_ports: PortSpec[]
  forward_ports: ForwardPortSpec[]
  icmp_blocks: string[]
  icmp_block_inversion: boolean
  masquerade: boolean
  forward: boolean
  interfaces: string[]
  sources: string[]
  rich_rules: { rule: string; parsed: RichRule | null }[]
  ingress_priority: number
  egress_priority: number
  /** Permanent view only. */
  builtin?: boolean
  modified?: boolean
}

export interface ZoneDetail {
  name: string
  runtime: ZoneView | null
  permanent: ZoneView | null
}

export interface PolicyView extends Omit<ZoneView, 'interfaces' | 'sources' | 'forward' | 'icmp_block_inversion' | 'ingress_priority' | 'egress_priority'> {
  ingress_zones: string[]
  egress_zones: string[]
  priority: number
  disable: boolean
}

export interface PolicyDetail {
  name: string
  runtime: PolicyView | null
  permanent: PolicyView | null
}

export interface PolicySummary {
  name: string
  runtime: boolean
  permanent: boolean
  active: boolean
  ingress_zones: string[]
  egress_zones: string[]
  priority: number
  target: string
  short: string
  disable: boolean
}

export type Scope = 'zone' | 'policy'

export interface RiskResult {
  level: 'ok' | 'warning' | 'danger'
  warnings: { level: 'warning' | 'danger'; message: string }[]
  connections: { what: string; before: string; after: string; decided_by: string }[]
  force_safe: boolean
}

export interface TesterStep {
  stage: string
  item: string
  result: 'match' | 'no-match' | 'unknown'
  detail: string
  verdict: string | null
}

export interface TesterResult {
  zone: string
  zone_reason: string
  verdict: 'ACCEPT' | 'REJECT' | 'DROP' | 'FORWARDED'
  decided_by: string
  steps: TesterStep[]
  notes: string[]
}

export interface DeniedEntry {
  ts: string
  prefix: string
  in: string
  out: string
  src: string
  dst: string
  proto: string
  spt: number | null
  dpt: number | null
  len: number | null
  icmp_type: string
  zone: string
  policy?: string
  action: string
  kind: 'denied' | 'logged' | 'invalid'
  cursor: string
}

export interface HistoryEntry {
  id: string
  short: string
  author: string
  date: string
  message: string
  stat: string
  external: boolean
}

export interface HistoryLog {
  enabled: boolean
  firewalld_dir: string
  watch_interval: number
  entries: HistoryEntry[]
}

export interface TemplateParam {
  name: string
  label: string
  type: 'zone' | 'text' | 'bool' | 'select' | 'textarea' | 'service'
  placeholder?: string
  default?: string | boolean
  options?: string[]
}

export interface Template {
  id: string
  title: string
  description: string
  params: TemplateParam[]
}

export interface Host {
  id: string
  name: string
  url: string
  verify_tls: boolean
  ca_pem: string
  token_set: boolean
}

export interface DirectRules {
  chains: { ipv: string; table: string; chain: string }[]
  rules: { ipv: string; table: string; chain: string; priority: number; args: string[] }[]
  passthroughs: { ipv: string; args: string[] }[]
}

export interface NotificationSettings {
  webhook_url: string
  syslog: boolean
  email_to: string
  email_from: string
  smtp_host: string
  smtp_port: number
  smtp_starttls: boolean
  smtp_user: string
  smtp_password_set: boolean
  events: 'changes' | 'all'
}

export interface ImportPlanItem {
  kind: 'zones' | 'policies' | 'services' | 'ipsets'
  name: string
  action: 'create' | 'update' | 'unchanged'
  changes: string[]
}

export type OpKind =
  | 'service'
  | 'port'
  | 'protocol'
  | 'source-port'
  | 'forward-port'
  | 'icmp-block'
  | 'rich-rule'
  | 'interface'
  | 'source'
  | 'masquerade'
  | 'forward'
  | 'icmp-block-inversion'
  | 'ingress-zone'
  | 'egress-zone'

export interface Op {
  action: 'add' | 'remove'
  kind: OpKind
  /** Zone name, or policy name when scope is 'policy'. */
  zone: string
  value: Record<string, string>
  scope?: 'zone' | 'policy'
}

export interface Service {
  name: string
  short: string
  description: string
  ports: PortSpec[]
  protocols: string[]
  source_ports: PortSpec[]
  modules: string[]
  helpers: string[]
  includes: string[]
  destination: { ipv4?: string; ipv6?: string }
  builtin: boolean
  modified: boolean
  runtime: boolean
}

export interface IPSet {
  name: string
  type: string
  options: Record<string, string>
  entries: string[]
}

export interface PendingChange {
  id: string
  user: string
  ops: Op[]
  persist: boolean
  seconds_left: number
}

export interface AuditEntry {
  ts: string
  user: string
  action: string
  ok: boolean
  detail: Record<string, unknown>
}

export interface Me {
  user: string
  csrf: string
  role: 'admin' | 'viewer'
  safe_apply_seconds: number
  dev_mode: boolean
  hostname: string
  tls: boolean
}

export interface SocketRow {
  proto: string
  state: string
  local_addr: string
  local_port: string
  peer_addr: string
  peer_port: string
  process: string
  pid: number | null
  listening: boolean
  peer_class: string
  direction: 'in' | 'out' | 'listen'
}

export interface ConntrackRow {
  proto: string
  state: string
  src: string
  dst: string
  sport: string
  dport: string
  nat: boolean
  assured: boolean
  src_class: string
}

export interface ConnectionsData {
  sockets: SocketRow[]
  conntrack: ConntrackRow[]
  conntrack_error: string
  processes_visible: boolean
}

export interface DeniedStats {
  hours: number
  bucket_minutes: number
  total: number
  unique_sources: number
  timeline: { t: string; count: number }[]
  top_sources: { src: string; count: number; ports: string[] }[]
  top_ports: { port: string; count: number }[]
  top_zones: { zone: string; count: number }[]
  top_interfaces: { interface: string; count: number }[]
  port?: number
  top_sources_on_port?: { src: string; count: number }[]
}

export interface Jail {
  name: string
  currently_failed: number
  total_failed: number
  currently_banned: number
  total_banned: number
  banned: string[]
  files: string
  bantime: number | null
  findtime: number | null
  maxretry: number | null
  actions: string[]
  uses_firewalld: boolean
  managed_settings?: Record<string, string>
}

export interface Fail2banStatus {
  installed: boolean
  running: boolean
  version?: string
  jails: Jail[]
  filters: string[]
  managed?: string[]
  error?: string
  hint?: string
}

export interface DdnsEntry {
  id: string
  hostname: string
  template: RichRule
  zone: string
  scope: 'zone' | 'policy'
  interval: number
  applied: Record<string, string>
  resolved?: string[]
  last_check: number
  last_error: string
  created_by: string
}

export interface Backup {
  id: string
  name: string
  created: string
  host: string
  user: string
  source: 'manual' | 'auto' | 'upload'
  has_files: boolean
  zones?: number
  policies?: number
  size: number
}

export interface Feed {
  url: string
  interval_hours: number
  last_check?: number
  last_ok?: number
  last_error?: string
  count?: number
}
