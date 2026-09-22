import { CheckCircle2Icon, Loader2Icon, XCircleIcon } from 'lucide-react'
import { useEffect, useId, useState, type ReactNode } from 'react'
import { parseRule, renderRule, useIcmpTypes, useIPSets, useServices } from '@/api/hooks'
import type { RichRule } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Textarea } from '@/components/ui/textarea'
import { emptyForm, formToRule, ruleToForm, type RuleForm } from '@/lib/rule-form'

const NONE = '__none__'
const PROTOCOLS = ['tcp', 'udp', 'sctp', 'dccp']
const IP_PROTOCOLS = ['tcp', 'udp', 'icmp', 'ipv6-icmp', 'sctp', 'dccp', 'gre', 'esp', 'ah', 'igmp', 'vrrp', 'ospf']
const LOG_LEVELS = ['emerg', 'alert', 'crit', 'error', 'warning', 'notice', 'info', 'debug']
const REJECT_TYPES = [
  'icmp-net-unreachable',
  'icmp-host-unreachable',
  'icmp-port-unreachable',
  'icmp-proto-unreachable',
  'icmp-net-prohibited',
  'icmp-host-prohibited',
  'icmp-admin-prohibited',
  'tcp-reset',
  'icmp6-no-route',
  'icmp6-adm-prohibited',
  'icmp6-addr-unreachable',
  'icmp6-port-unreachable',
]
const ELEMENTS: { value: RuleForm['element']; label: string }[] = [
  { value: 'service', label: 'Service' },
  { value: 'port', label: 'Port' },
  { value: 'source-port', label: 'Source port' },
  { value: 'protocol', label: 'Protocol' },
  { value: 'icmp-block', label: 'ICMP block' },
  { value: 'icmp-type', label: 'ICMP type' },
  { value: 'forward-port', label: 'Forward port' },
  { value: 'masquerade', label: 'Masquerade' },
  { value: 'tcp-mss-clamp', label: 'TCP MSS clamp' },
]

export interface RuleSubmit {
  rule: string
  /** Seconds; when set, add at runtime only and let firewalld expire it. */
  timeout?: number
}

interface Props {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Existing rule when editing; omit to create. */
  initial?: { rule: string; parsed: RichRule | null }
  title: string
  submitLabel: string
  allowTimeout?: boolean
  onSubmit: (v: RuleSubmit) => Promise<unknown>
}

function Field({ label, children, className }: { label: string; children: ReactNode; className?: string }) {
  const id = useId()
  return (
    <div className={`grid gap-1.5 ${className ?? ''}`}>
      <Label htmlFor={id} className="text-xs text-muted-foreground">
        {label}
      </Label>
      <div id={id}>{children}</div>
    </div>
  )
}

function SimpleSelect({
  value,
  onChange,
  options,
  placeholder,
}: {
  value: string
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  placeholder?: string
}) {
  return (
    <Select value={value === '' ? NONE : value} onValueChange={(v) => onChange(v === NONE ? '' : v)}>
      <SelectTrigger className="w-full">
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent>
        {options.map((o) => (
          <SelectItem key={o.value || NONE} value={o.value || NONE}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

function Section({ title, children }: { title: string; children: ReactNode }) {
  return (
    <fieldset className="grid gap-3">
      <legend className="mb-2 text-sm font-medium">{title}</legend>
      {children}
    </fieldset>
  )
}

function LimitInputs({
  value,
  burst,
  onValue,
  onBurst,
  label = 'Rate limit',
}: {
  value: string
  burst: string
  onValue: (v: string) => void
  onBurst: (v: string) => void
  label?: string
}) {
  return (
    <div className="grid grid-cols-[1fr_6rem] gap-2">
      <Field label={`${label} (e.g. 3/m)`}>
        <Input value={value} onChange={(e) => onValue(e.target.value)} placeholder="none" />
      </Field>
      <Field label="Burst">
        <Input value={burst} onChange={(e) => onBurst(e.target.value)} inputMode="numeric" disabled={!value} />
      </Field>
    </div>
  )
}

type Check = { state: 'idle' | 'checking' | 'valid' | 'invalid'; rule?: string; error?: string }

function useDebounced<T>(value: T, ms: number) {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}

export function RichRuleBuilder({ open, onOpenChange, initial, title, submitLabel, allowTimeout, onSubmit }: Props) {
  const services = useServices()
  const icmpTypes = useIcmpTypes()
  const ipsets = useIPSets()

  // State is initialized from props on mount; callers remount (via `key`) for each open.
  const [mode, setMode] = useState<'builder' | 'raw'>(initial && !initial.parsed ? 'raw' : 'builder')
  const [form, setForm] = useState<RuleForm>(() => (initial?.parsed ? ruleToForm(initial.parsed) : emptyForm))
  const [raw, setRaw] = useState(initial?.rule ?? '')
  const [check, setCheck] = useState<Check>({ state: 'idle' })
  const [temporary, setTemporary] = useState(false)
  const [timeout, setTimeoutSecs] = useState('300')
  const [submitting, setSubmitting] = useState(false)

  const set = <K extends keyof RuleForm>(k: K, v: RuleForm[K]) => setForm((f) => ({ ...f, [k]: v }))

  // Live validation against firewalld's parser.
  const debouncedForm = useDebounced(form, 250)
  const debouncedRaw = useDebounced(raw, 250)
  useEffect(() => {
    if (!open) return
    let cancelled = false
    const input = mode === 'builder' ? debouncedForm : debouncedRaw
    if (mode === 'raw' && !debouncedRaw.trim()) {
      setCheck({ state: 'idle' })
      return
    }
    setCheck((c) => ({ ...c, state: 'checking' }))
    const p = mode === 'builder' ? renderRule(formToRule(input as RuleForm)) : parseRule(input as string)
    p.then(
      (r) => !cancelled && setCheck(r.valid ? { state: 'valid', rule: r.rule } : { state: 'invalid', error: r.error }),
      (e: Error) => !cancelled && setCheck({ state: 'invalid', error: e.message }),
    )
    return () => {
      cancelled = true
    }
  }, [open, mode, debouncedForm, debouncedRaw])

  async function switchMode(next: string) {
    if (next === 'raw' && check.state === 'valid' && check.rule) setRaw(check.rule)
    if (next === 'builder' && raw.trim()) {
      const r = await parseRule(raw)
      if (r.valid && r.parsed) setForm(ruleToForm(r.parsed))
    }
    setMode(next as 'builder' | 'raw')
  }

  async function submit() {
    if (check.state !== 'valid' || !check.rule) return
    setSubmitting(true)
    try {
      await onSubmit({ rule: check.rule, timeout: temporary ? Number(timeout) || 0 : undefined })
      onOpenChange(false)
    } catch {
      /* error already shown as a toast; keep the dialog open */
    } finally {
      setSubmitting(false)
    }
  }

  const el = form.element
  const ipsetNames = [...new Set([...(ipsets.data?.runtime ?? []), ...(ipsets.data?.permanent ?? [])].map((s) => s.name))]

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92svh] overflow-y-auto sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription>
            Rules are validated live by firewalld's own rich rule parser.
          </DialogDescription>
        </DialogHeader>

        <datalist id="rr-services">
          {services.data?.map((s) => (
            <option key={s.name} value={s.name}>
              {s.short}
            </option>
          ))}
        </datalist>
        <datalist id="rr-icmp">
          {icmpTypes.data?.map((t) => <option key={t} value={t} />)}
        </datalist>
        <datalist id="rr-ipsets">
          {ipsetNames.map((n) => <option key={n} value={n} />)}
        </datalist>
        <datalist id="rr-ipproto">
          {IP_PROTOCOLS.map((p) => <option key={p} value={p} />)}
        </datalist>

        <Tabs value={mode} onValueChange={switchMode}>
          <TabsList>
            <TabsTrigger value="builder">Builder</TabsTrigger>
            <TabsTrigger value="raw">Raw rule</TabsTrigger>
          </TabsList>

          <TabsContent value="builder" className="mt-4 grid gap-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <Field label="Family">
                <SimpleSelect
                  value={form.family}
                  onChange={(v) => set('family', v as RuleForm['family'])}
                  options={[
                    { value: '', label: 'Any' },
                    { value: 'ipv4', label: 'IPv4' },
                    { value: 'ipv6', label: 'IPv6' },
                  ]}
                />
              </Field>
              <Field label="Priority (-32768…32767)">
                <Input type="number" value={form.priority} onChange={(e) => set('priority', e.target.value)} />
              </Field>
            </div>

            <Separator />
            <div className="grid gap-5 md:grid-cols-2">
              <Section title="Source">
                <div className="grid grid-cols-[8rem_1fr] gap-2">
                  <SimpleSelect
                    value={form.srcType}
                    onChange={(v) => set('srcType', v as RuleForm['srcType'])}
                    options={[
                      { value: '', label: 'Any' },
                      { value: 'addr', label: 'Address' },
                      { value: 'mac', label: 'MAC' },
                      { value: 'ipset', label: 'IP set' },
                    ]}
                  />
                  <Input
                    disabled={!form.srcType}
                    value={form.srcValue}
                    onChange={(e) => set('srcValue', e.target.value)}
                    list={form.srcType === 'ipset' ? 'rr-ipsets' : undefined}
                    placeholder={
                      form.srcType === 'mac' ? '00:11:22:33:44:55' : form.srcType === 'ipset' ? 'ipset name' : '192.168.1.0/24'
                    }
                  />
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={form.srcInvert}
                    disabled={!form.srcType}
                    onCheckedChange={(c) => set('srcInvert', c === true)}
                  />
                  NOT (invert match)
                </label>
              </Section>

              <Section title="Destination">
                <div className="grid grid-cols-[8rem_1fr] gap-2">
                  <SimpleSelect
                    value={form.dstType}
                    onChange={(v) => set('dstType', v as RuleForm['dstType'])}
                    options={[
                      { value: '', label: 'Any' },
                      { value: 'addr', label: 'Address' },
                      { value: 'ipset', label: 'IP set' },
                    ]}
                  />
                  <Input
                    disabled={!form.dstType}
                    value={form.dstValue}
                    onChange={(e) => set('dstValue', e.target.value)}
                    list={form.dstType === 'ipset' ? 'rr-ipsets' : undefined}
                    placeholder={form.dstType === 'ipset' ? 'ipset name' : '10.0.0.1'}
                  />
                </div>
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox
                    checked={form.dstInvert}
                    disabled={!form.dstType}
                    onCheckedChange={(c) => set('dstInvert', c === true)}
                  />
                  NOT (invert match)
                </label>
              </Section>
            </div>

            <Separator />
            <Section title="Match">
              <div className="grid gap-3 sm:grid-cols-4">
                <Field label="Element">
                  <SimpleSelect
                    value={el}
                    onChange={(v) => set('element', v as RuleForm['element'])}
                    options={[{ value: '', label: 'None' }, ...ELEMENTS]}
                  />
                </Field>
                {(el === 'service' || el === 'icmp-block' || el === 'icmp-type') && (
                  <Field label={el === 'service' ? 'Service name' : 'ICMP type'} className="sm:col-span-3">
                    <Input
                      value={form.elName}
                      onChange={(e) => set('elName', e.target.value)}
                      list={el === 'service' ? 'rr-services' : 'rr-icmp'}
                      placeholder={el === 'service' ? 'ssh' : 'echo-request'}
                    />
                  </Field>
                )}
                {(el === 'port' || el === 'source-port' || el === 'forward-port') && (
                  <>
                    <Field label="Port or range">
                      <Input value={form.elPort} onChange={(e) => set('elPort', e.target.value)} placeholder="8080 or 1000-2000" />
                    </Field>
                    <Field label="Protocol">
                      <SimpleSelect
                        value={form.elProtocol}
                        onChange={(v) => set('elProtocol', v)}
                        options={PROTOCOLS.map((p) => ({ value: p, label: p }))}
                      />
                    </Field>
                  </>
                )}
                {el === 'forward-port' && (
                  <>
                    <Field label="To port">
                      <Input value={form.elToPort} onChange={(e) => set('elToPort', e.target.value)} placeholder="optional" />
                    </Field>
                    <Field label="To address" className="sm:col-start-2 sm:col-span-2">
                      <Input value={form.elToAddr} onChange={(e) => set('elToAddr', e.target.value)} placeholder="optional" />
                    </Field>
                  </>
                )}
                {el === 'protocol' && (
                  <Field label="Protocol (name or number)" className="sm:col-span-3">
                    <Input value={form.elValue} onChange={(e) => set('elValue', e.target.value)} list="rr-ipproto" placeholder="icmp" />
                  </Field>
                )}
                {el === 'tcp-mss-clamp' && (
                  <Field label="MSS value (blank = pmtu)" className="sm:col-span-3">
                    <Input value={form.elValue} onChange={(e) => set('elValue', e.target.value)} placeholder="pmtu" />
                  </Field>
                )}
              </div>
            </Section>

            <Separator />
            <div className="grid gap-5 md:grid-cols-2">
              <Section title="Logging">
                <Field label="Log type">
                  <SimpleSelect
                    value={form.logType}
                    onChange={(v) => set('logType', v as RuleForm['logType'])}
                    options={[
                      { value: '', label: 'None' },
                      { value: 'log', label: 'log (kernel log)' },
                      { value: 'nflog', label: 'nflog (userspace)' },
                    ]}
                  />
                </Field>
                {form.logType && (
                  <>
                    <div className="grid grid-cols-2 gap-2">
                      <Field label="Prefix">
                        <Input value={form.logPrefix} onChange={(e) => set('logPrefix', e.target.value)} maxLength={127} />
                      </Field>
                      {form.logType === 'log' ? (
                        <Field label="Level">
                          <SimpleSelect
                            value={form.logLevel}
                            onChange={(v) => set('logLevel', v)}
                            options={[{ value: '', label: 'default' }, ...LOG_LEVELS.map((l) => ({ value: l, label: l }))]}
                          />
                        </Field>
                      ) : (
                        <div className="grid grid-cols-2 gap-2">
                          <Field label="Group">
                            <Input value={form.nflogGroup} onChange={(e) => set('nflogGroup', e.target.value)} inputMode="numeric" />
                          </Field>
                          <Field label="Queue size">
                            <Input
                              value={form.nflogThreshold}
                              onChange={(e) => set('nflogThreshold', e.target.value)}
                              inputMode="numeric"
                            />
                          </Field>
                        </div>
                      )}
                    </div>
                    <LimitInputs
                      value={form.logLimit}
                      burst={form.logBurst}
                      onValue={(v) => set('logLimit', v)}
                      onBurst={(v) => set('logBurst', v)}
                      label="Log limit"
                    />
                  </>
                )}
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={form.audit} onCheckedChange={(c) => set('audit', c === true)} />
                  Audit (send to the audit subsystem)
                </label>
                {form.audit && (
                  <LimitInputs
                    value={form.auditLimit}
                    burst={form.auditBurst}
                    onValue={(v) => set('auditLimit', v)}
                    onBurst={(v) => set('auditBurst', v)}
                    label="Audit limit"
                  />
                )}
              </Section>

              <Section title="Action">
                <Field label="Action">
                  <SimpleSelect
                    value={form.action}
                    onChange={(v) => set('action', v as RuleForm['action'])}
                    options={[
                      { value: '', label: 'None' },
                      { value: 'accept', label: 'Accept' },
                      { value: 'reject', label: 'Reject' },
                      { value: 'drop', label: 'Drop' },
                      { value: 'mark', label: 'Mark' },
                    ]}
                  />
                </Field>
                {form.action === 'reject' && (
                  <Field label="Reject with">
                    <SimpleSelect
                      value={form.rejectType}
                      onChange={(v) => set('rejectType', v)}
                      options={[{ value: '', label: 'default' }, ...REJECT_TYPES.map((t) => ({ value: t, label: t }))]}
                    />
                  </Field>
                )}
                {form.action === 'mark' && (
                  <Field label="Mark (value[/mask])">
                    <Input value={form.markSet} onChange={(e) => set('markSet', e.target.value)} placeholder="0x1/0xff" />
                  </Field>
                )}
                {form.action && (
                  <LimitInputs
                    value={form.actionLimit}
                    burst={form.actionBurst}
                    onValue={(v) => set('actionLimit', v)}
                    onBurst={(v) => set('actionBurst', v)}
                  />
                )}
              </Section>
            </div>
          </TabsContent>

          <TabsContent value="raw" className="mt-4 grid gap-2">
            <Label htmlFor="rr-raw" className="text-xs text-muted-foreground">
              Rich rule (firewall-cmd syntax)
            </Label>
            <Textarea
              id="rr-raw"
              value={raw}
              onChange={(e) => setRaw(e.target.value)}
              rows={4}
              className="font-mono text-sm"
              placeholder={'rule family="ipv4" source address="10.0.0.0/8" service name="ssh" accept'}
              spellCheck={false}
            />
          </TabsContent>
        </Tabs>

        <div
          className={`rounded-md border p-3 font-mono text-xs break-all ${
            check.state === 'invalid' ? 'border-destructive/50 bg-destructive/5' : 'bg-muted/50'
          }`}
        >
          <div className="mb-1 flex items-center gap-1.5 font-sans text-xs font-medium">
            {check.state === 'checking' && <Loader2Icon className="size-3.5 animate-spin" />}
            {check.state === 'valid' && <CheckCircle2Icon className="size-3.5 text-emerald-600" />}
            {check.state === 'invalid' && <XCircleIcon className="size-3.5 text-destructive" />}
            {check.state === 'invalid' ? 'Invalid rule' : 'Rule preview'}
          </div>
          {check.state === 'invalid' ? (
            <span className="text-destructive">{check.error}</span>
          ) : (
            <span>{check.rule ?? '…'}</span>
          )}
        </div>

        <DialogFooter className="items-center gap-3 sm:justify-between">
          {allowTimeout ? (
            <div className="flex items-center gap-2 text-sm">
              <Checkbox id="rr-temp" checked={temporary} onCheckedChange={(c) => setTemporary(c === true)} />
              <Label htmlFor="rr-temp" className="font-normal">
                Temporary: runtime only, expires after
              </Label>
              <Input
                className="h-8 w-20"
                value={timeout}
                onChange={(e) => setTimeoutSecs(e.target.value)}
                disabled={!temporary}
                inputMode="numeric"
                aria-label="Timeout in seconds"
              />
              <span className="text-muted-foreground">s</span>
            </div>
          ) : (
            <span />
          )}
          <div className="flex gap-2">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            <Button onClick={submit} disabled={check.state !== 'valid' || submitting}>
              {submitting && <Loader2Icon className="animate-spin" />}
              {submitLabel}
            </Button>
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
