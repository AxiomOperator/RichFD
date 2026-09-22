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

export interface Op {
  action: 'add' | 'remove'
  kind: OpKind
  zone: string
  value: Record<string, string>
}

export interface Service {
  name: string
  short: string
  description: string
  ports: PortSpec[]
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
  safe_apply_seconds: number
  dev_mode: boolean
}
