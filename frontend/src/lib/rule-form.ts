import type { Limit, RichRule, RuleElement } from '@/api/types'

/** Flat, input-friendly representation of a rich rule for the builder form. */
export interface RuleForm {
  family: '' | 'ipv4' | 'ipv6'
  priority: string
  srcType: '' | 'addr' | 'mac' | 'ipset'
  srcValue: string
  srcInvert: boolean
  dstType: '' | 'addr' | 'ipset'
  dstValue: string
  dstInvert: boolean
  element: '' | RuleElement['type']
  elName: string
  elPort: string
  elProtocol: string
  elValue: string
  elToPort: string
  elToAddr: string
  logType: '' | 'log' | 'nflog'
  logPrefix: string
  logLevel: string
  logLimit: string
  logBurst: string
  nflogGroup: string
  nflogThreshold: string
  audit: boolean
  auditLimit: string
  auditBurst: string
  action: '' | 'accept' | 'reject' | 'drop' | 'mark'
  rejectType: string
  markSet: string
  actionLimit: string
  actionBurst: string
}

export const emptyForm: RuleForm = {
  family: '',
  priority: '0',
  srcType: '',
  srcValue: '',
  srcInvert: false,
  dstType: '',
  dstValue: '',
  dstInvert: false,
  element: 'service',
  elName: '',
  elPort: '',
  elProtocol: 'tcp',
  elValue: '',
  elToPort: '',
  elToAddr: '',
  logType: '',
  logPrefix: '',
  logLevel: '',
  logLimit: '',
  logBurst: '',
  nflogGroup: '',
  nflogThreshold: '',
  audit: false,
  auditLimit: '',
  auditBurst: '',
  action: 'accept',
  rejectType: '',
  markSet: '',
  actionLimit: '',
  actionBurst: '',
}

const limit = (value: string, burst: string): Limit | null =>
  value.trim() ? { value: value.trim(), burst: Number(burst) || 0 } : null

const int = (s: string) => {
  const n = Number(s)
  return Number.isFinite(n) ? Math.trunc(n) : 0
}

export function formToRule(f: RuleForm): RichRule {
  let element: RuleElement | null = null
  switch (f.element) {
    case 'service':
    case 'icmp-block':
    case 'icmp-type':
      element = { type: f.element, name: f.elName.trim() }
      break
    case 'port':
    case 'source-port':
      element = { type: f.element, port: f.elPort.trim(), protocol: f.elProtocol }
      break
    case 'protocol':
      element = { type: 'protocol', value: f.elValue.trim() }
      break
    case 'tcp-mss-clamp':
      element = { type: 'tcp-mss-clamp', value: f.elValue.trim() }
      break
    case 'masquerade':
      element = { type: 'masquerade' }
      break
    case 'forward-port':
      element = {
        type: 'forward-port',
        port: f.elPort.trim(),
        protocol: f.elProtocol,
        to_port: f.elToPort.trim(),
        to_addr: f.elToAddr.trim(),
      }
      break
  }

  const src = f.srcValue.trim()
  const dst = f.dstValue.trim()
  return {
    family: f.family,
    priority: int(f.priority),
    source:
      f.srcType && src
        ? {
            addr: f.srcType === 'addr' ? src : '',
            mac: f.srcType === 'mac' ? src : '',
            ipset: f.srcType === 'ipset' ? src : '',
            invert: f.srcInvert,
          }
        : null,
    destination:
      f.dstType && dst
        ? { addr: f.dstType === 'addr' ? dst : '', ipset: f.dstType === 'ipset' ? dst : '', invert: f.dstInvert }
        : null,
    element,
    log:
      f.logType === 'log'
        ? { type: 'log', prefix: f.logPrefix, level: f.logLevel, limit: limit(f.logLimit, f.logBurst) }
        : f.logType === 'nflog'
          ? {
              type: 'nflog',
              group: int(f.nflogGroup),
              prefix: f.logPrefix,
              threshold: int(f.nflogThreshold),
              limit: limit(f.logLimit, f.logBurst),
            }
          : null,
    audit: f.audit ? { limit: limit(f.auditLimit, f.auditBurst) } : null,
    action: f.action
      ? {
          type: f.action,
          reject_type: f.action === 'reject' ? f.rejectType : '',
          set: f.action === 'mark' ? f.markSet.trim() : '',
          limit: limit(f.actionLimit, f.actionBurst),
        }
      : null,
  }
}

export function ruleToForm(r: RichRule): RuleForm {
  const f: RuleForm = { ...emptyForm, element: '', action: '' }
  f.family = r.family
  f.priority = String(r.priority ?? 0)
  if (r.source) {
    f.srcType = r.source.addr ? 'addr' : r.source.mac ? 'mac' : 'ipset'
    f.srcValue = r.source.addr || r.source.mac || r.source.ipset
    f.srcInvert = r.source.invert
  }
  if (r.destination) {
    f.dstType = r.destination.addr ? 'addr' : 'ipset'
    f.dstValue = r.destination.addr || r.destination.ipset
    f.dstInvert = r.destination.invert
  }
  const el = r.element
  if (el) {
    f.element = el.type
    if ('name' in el) f.elName = el.name
    if ('port' in el) {
      f.elPort = el.port
      f.elProtocol = el.protocol
    }
    if ('value' in el) f.elValue = el.value
    if (el.type === 'forward-port') {
      f.elToPort = el.to_port
      f.elToAddr = el.to_addr
    }
  }
  if (r.log) {
    f.logType = r.log.type
    f.logPrefix = r.log.prefix
    f.logLimit = r.log.limit?.value ?? ''
    f.logBurst = r.log.limit?.burst ? String(r.log.limit.burst) : ''
    if (r.log.type === 'log') f.logLevel = r.log.level
    else {
      f.nflogGroup = r.log.group ? String(r.log.group) : ''
      f.nflogThreshold = r.log.threshold ? String(r.log.threshold) : ''
    }
  }
  if (r.audit) {
    f.audit = true
    f.auditLimit = r.audit.limit?.value ?? ''
    f.auditBurst = r.audit.limit?.burst ? String(r.audit.limit.burst) : ''
  }
  if (r.action) {
    f.action = r.action.type
    f.rejectType = r.action.reject_type
    f.markSet = r.action.set
    f.actionLimit = r.action.limit?.value ?? ''
    f.actionBurst = r.action.limit?.burst ? String(r.action.limit.burst) : ''
  }
  return f
}

/** Short human-readable pieces of a parsed rule, for table columns. */
export function describe(r: RichRule) {
  const inv = (b: boolean) => (b ? 'NOT ' : '')
  const source = r.source
    ? `${inv(r.source.invert)}${r.source.addr || (r.source.mac && `mac ${r.source.mac}`) || `ipset:${r.source.ipset}`}`
    : 'any'
  const destination = r.destination
    ? `${inv(r.destination.invert)}${r.destination.addr || `ipset:${r.destination.ipset}`}`
    : 'any'
  let element = '—'
  const el = r.element
  if (el) {
    switch (el.type) {
      case 'service':
        element = `service ${el.name}`
        break
      case 'port':
        element = `port ${el.port}/${el.protocol}`
        break
      case 'source-port':
        element = `source-port ${el.port}/${el.protocol}`
        break
      case 'protocol':
        element = `protocol ${el.value}`
        break
      case 'icmp-block':
        element = `icmp-block ${el.name}`
        break
      case 'icmp-type':
        element = `icmp-type ${el.name}`
        break
      case 'masquerade':
        element = 'masquerade'
        break
      case 'forward-port':
        element = `forward ${el.port}/${el.protocol} → ${el.to_addr || ''}${el.to_port ? `:${el.to_port}` : ''}`
        break
      case 'tcp-mss-clamp':
        element = `tcp-mss-clamp ${el.value || 'pmtu'}`
        break
    }
  }
  const extras = [
    r.log && (r.log.type === 'log' ? `log${r.log.prefix ? ` "${r.log.prefix}"` : ''}` : 'nflog'),
    r.audit && 'audit',
  ].filter(Boolean) as string[]
  let action = r.action?.type ?? (el && ['masquerade', 'forward-port', 'icmp-block', 'tcp-mss-clamp'].includes(el.type) ? '(implicit)' : '—')
  if (r.action?.type === 'reject' && r.action.reject_type) action += ` (${r.action.reject_type})`
  if (r.action?.type === 'mark') action += ` ${r.action.set}`
  if (r.action?.limit) action += ` ≤${r.action.limit.value}`
  return { source, destination, element, extras, action }
}
