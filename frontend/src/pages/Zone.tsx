import { CopyIcon, PencilIcon, PlusIcon, RotateCcwIcon, StarIcon, Trash2Icon } from 'lucide-react'
import { useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { useNavigate, useParams } from 'react-router'
import { api } from '@/api/client'
import { useFwMutation, useIcmpTypes, useServices, useStatus, useZone } from '@/api/hooks'
import type { ForwardPortSpec, OpKind, PortSpec, RichRule, ZoneView } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { PresenceBadge } from '@/components/PresenceBadge'
import { RichRuleBuilder, type RuleSubmit } from '@/components/RichRuleBuilder'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { describe } from '@/lib/rule-form'
import { mergeItems, removalTarget, useZoneOps, type Merged, type Presence } from '@/lib/zone-ops'

type Ops = ReturnType<typeof useZoneOps>

const PROTOCOLS = ['tcp', 'udp', 'sctp', 'dccp']
const portKey = (p: PortSpec) => `${p.port}/${p.protocol}`
const fwdKey = (p: ForwardPortSpec) => `${p.port}/${p.protocol}>${p.to_addr}:${p.to_port}`

// -- rich rules ------------------------------------------------------------------

type RuleEntry = { rule: string; parsed: RichRule | null }

function RichRulesTab({
  zone,
  runtime,
  permanent,
  ops,
}: {
  zone: string
  runtime?: ZoneView
  permanent?: ZoneView
  ops: Ops
}) {
  const rules = useMemo(
    () =>
      mergeItems(runtime?.rich_rules, permanent?.rich_rules, (r) => r.rule).sort(
        (a, b) => (a.item.parsed?.priority ?? 0) - (b.item.parsed?.priority ?? 0),
      ),
    [runtime, permanent],
  )
  const [dialog, setDialog] = useState<{ mode: 'add' | 'edit' | 'dup'; entry?: Merged<RuleEntry> } | null>(null)
  const [filter, setFilter] = useState('')
  const shown = rules.filter((r) => r.item.rule.toLowerCase().includes(filter.toLowerCase()))

  async function submit({ rule, timeout }: RuleSubmit) {
    if (dialog?.mode === 'edit' && dialog.entry) {
      const old = dialog.entry
      if (old.item.rule === rule) return
      const where = removalTarget(old, ops.target)
      if (!where) throw new Error('Rule is not present in the selected configuration')
      // Remove + add in one atomic batch so a failed add restores the old rule.
      await ops.run(
        [ops.op('remove', 'rich-rule', { rule: old.item.rule }), ops.op('add', 'rich-rule', { rule })],
        where,
      )
    } else {
      await ops.add('rich-rule', { rule }, { timeout })
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Rich rules</CardTitle>
        <CardDescription>
          Evaluated by priority (lowest first). Rules with priority 0 run after zone services and ports.
        </CardDescription>
        <CardAction className="flex gap-2">
          <Input
            placeholder="Filter…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="h-8 w-40"
          />
          <Button size="sm" onClick={() => setDialog({ mode: 'add' })}>
            <PlusIcon /> Add rule
          </Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        {rules.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">No rich rules in zone {zone}.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-12">Prio</TableHead>
                <TableHead className="w-14">Family</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Match</TableHead>
                <TableHead>Action</TableHead>
                <TableHead className="w-40" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((r) => {
                const d = r.item.parsed ? describe(r.item.parsed) : null
                const action = r.item.parsed?.action?.type
                return (
                  <TableRow key={r.key} className="align-top">
                    {d ? (
                      <>
                        <TableCell className="tabular-nums">{r.item.parsed!.priority}</TableCell>
                        <TableCell>{r.item.parsed!.family || 'any'}</TableCell>
                        <TableCell className="font-mono text-xs">{d.source}</TableCell>
                        <TableCell className="font-mono text-xs">{d.destination}</TableCell>
                        <TableCell className="text-xs">
                          <div className="font-mono">{d.element}</div>
                          {d.extras.length > 0 && <div className="text-muted-foreground">{d.extras.join(', ')}</div>}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              action === 'accept'
                                ? 'default'
                                : action === 'drop' || action === 'reject'
                                  ? 'destructive'
                                  : 'secondary'
                            }
                          >
                            {d.action}
                          </Badge>
                          <div className="mt-1">
                            <PresenceBadge where={r} onSync={() => ops.sync('rich-rule', { rule: r.item.rule }, r)} />
                          </div>
                        </TableCell>
                      </>
                    ) : (
                      <TableCell colSpan={6} className="font-mono text-xs">
                        {r.item.rule}
                      </TableCell>
                    )}
                    <TableCell className="text-right whitespace-nowrap">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="Edit"
                            onClick={() => setDialog({ mode: 'edit', entry: r })}
                          >
                            <PencilIcon />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Edit</TooltipContent>
                      </Tooltip>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon-sm"
                            aria-label="Duplicate"
                            onClick={() => setDialog({ mode: 'dup', entry: r })}
                          >
                            <CopyIcon />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Duplicate</TooltipContent>
                      </Tooltip>
                      <ConfirmButton
                        size="icon-sm"
                        aria-label="Delete"
                        destructive
                        title="Delete rich rule?"
                        description={<code className="text-xs break-all">{r.item.rule}</code>}
                        confirmLabel="Delete"
                        onConfirm={() => ops.remove('rich-rule', { rule: r.item.rule }, r).catch(() => {})}
                      >
                        <Trash2Icon />
                      </ConfirmButton>
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
        {rules.length > 0 && (
          <details className="mt-4 text-xs">
            <summary className="cursor-pointer text-muted-foreground">Show raw rules</summary>
            <pre className="mt-2 overflow-x-auto rounded-md bg-muted p-3">
              {rules.map((r) => r.item.rule).join('\n')}
            </pre>
          </details>
        )}
      </CardContent>
      {dialog && (
        <RichRuleBuilder
          key={`${dialog.mode}:${dialog.entry?.key ?? ''}`}
          open
          onOpenChange={(o) => !o && setDialog(null)}
          initial={dialog?.entry?.item}
          title={dialog?.mode === 'edit' ? 'Edit rich rule' : 'New rich rule'}
          submitLabel={dialog?.mode === 'edit' ? 'Save' : 'Add rule'}
          allowTimeout={dialog?.mode !== 'edit'}
          onSubmit={submit}
        />
      )}
    </Card>
  )
}

// -- generic item lists --------------------------------------------------------------

function ItemList<T>({
  title,
  description,
  items,
  render,
  toValue,
  kind,
  ops,
  addForm,
  empty = 'None',
}: {
  title: string
  description?: string
  items: Merged<T>[]
  render: (t: T) => ReactNode
  toValue: (t: T) => Record<string, string>
  kind: OpKind
  ops: Ops
  addForm?: ReactNode
  empty?: string
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="grid gap-3">
        {addForm}
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {items.map((m) => (
              <li key={m.key} className="flex items-center gap-3 px-3 py-2 text-sm">
                <span className="min-w-0 flex-1 truncate font-mono">{render(m.item)}</span>
                <PresenceBadge where={m} onSync={() => ops.sync(kind, toValue(m.item), m)} />
                <ConfirmButton
                  size="icon-sm"
                  aria-label="Remove"
                  destructive
                  title={`Remove ${kind}?`}
                  description={<code>{render(m.item)}</code>}
                  confirmLabel="Remove"
                  onConfirm={() => ops.remove(kind, toValue(m.item), m).catch(() => {})}
                >
                  <Trash2Icon />
                </ConfirmButton>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  )
}

function InlineAdd({
  children,
  onSubmit,
  disabled,
}: {
  children: ReactNode
  onSubmit: () => Promise<unknown>
  disabled?: boolean
}) {
  const [busy, setBusy] = useState(false)
  async function submit(e: FormEvent) {
    e.preventDefault()
    setBusy(true)
    try {
      await onSubmit()
    } catch {
      /* toast shown */
    } finally {
      setBusy(false)
    }
  }
  return (
    <form onSubmit={submit} className="flex flex-wrap items-center gap-2">
      {children}
      <Button type="submit" size="sm" disabled={disabled || busy}>
        <PlusIcon /> Add
      </Button>
    </form>
  )
}

function ProtocolSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  return (
    <Select value={value} onValueChange={onChange}>
      <SelectTrigger size="sm" className="w-24" aria-label="Protocol">
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {PROTOCOLS.map((p) => (
          <SelectItem key={p} value={p}>
            {p}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

function ServicesTab({ runtime, permanent, ops }: TabProps) {
  const services = useServices()
  const [name, setName] = useState('')
  const items = mergeItems(runtime?.services, permanent?.services, (s) => s)
  const byName = new Map(services.data?.map((s) => [s.name, s]))
  const available = services.data?.filter((s) => !items.some((i) => i.key === s.name)) ?? []
  return (
    <ItemList
      title="Services"
      description="Predefined services allowed into this zone."
      items={items}
      kind="service"
      ops={ops}
      toValue={(s) => ({ name: s })}
      render={(s) => (
        <span>
          {s}{' '}
          <span className="font-sans text-xs text-muted-foreground">
            {byName.get(s)?.ports.map(portKey).join(', ')}
          </span>
        </span>
      )}
      addForm={
        <InlineAdd onSubmit={() => ops.add('service', { name }).then(() => setName(''))} disabled={!name}>
          <Select value={name} onValueChange={setName}>
            <SelectTrigger size="sm" className="w-72" aria-label="Service">
              <SelectValue placeholder="Choose a service…" />
            </SelectTrigger>
            <SelectContent className="max-h-80">
              {available.map((s) => (
                <SelectItem key={s.name} value={s.name}>
                  {s.name}
                  {s.short && s.short !== s.name && <span className="text-muted-foreground"> — {s.short}</span>}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </InlineAdd>
      }
    />
  )
}

function PortListTab({
  runtime,
  permanent,
  ops,
  kind,
  field,
  title,
  description,
}: TabProps & { kind: 'port' | 'source-port'; field: 'ports' | 'source_ports'; title: string; description: string }) {
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  return (
    <ItemList
      title={title}
      description={description}
      items={mergeItems(runtime?.[field], permanent?.[field], portKey)}
      kind={kind}
      ops={ops}
      toValue={(p) => ({ port: p.port, protocol: p.protocol })}
      render={portKey}
      addForm={
        <InlineAdd onSubmit={() => ops.add(kind, { port, protocol }).then(() => setPort(''))} disabled={!port}>
          <Input
            className="h-8 w-40"
            placeholder="port or 1000-2000"
            value={port}
            onChange={(e) => setPort(e.target.value)}
          />
          <ProtocolSelect value={protocol} onChange={setProtocol} />
        </InlineAdd>
      }
    />
  )
}

function ToggleRow({
  label,
  description,
  runtime,
  permanent,
  kind,
  ops,
}: {
  label: string
  description: string
  runtime?: boolean
  permanent?: boolean
  kind: OpKind
  ops: Ops
}) {
  const where: Presence = { runtime: !!runtime, permanent: !!permanent }
  const on =
    ops.target === 'runtime'
      ? where.runtime
      : ops.target === 'permanent'
        ? where.permanent
        : where.runtime && where.permanent
  const differs = where.runtime !== where.permanent
  return (
    <div className="flex items-center gap-4 py-3">
      <div className="flex-1">
        <div className="text-sm font-medium">{label}</div>
        <div className="text-xs text-muted-foreground">{description}</div>
      </div>
      {differs && (
        <span className="text-xs text-muted-foreground">
          runtime {where.runtime ? 'on' : 'off'} · permanent {where.permanent ? 'on' : 'off'}
        </span>
      )}
      <Switch
        checked={on}
        aria-label={label}
        onCheckedChange={(checked) => {
          // Only touch the configs whose state differs from the requested one.
          const need = { runtime: where.runtime !== checked, permanent: where.permanent !== checked }
          const t = removalTarget(need, ops.target)
          if (t) ops.run([ops.op(checked ? 'add' : 'remove', kind)], t).catch(() => {})
        }}
      />
    </div>
  )
}

function ForwardingTab({ runtime, permanent, ops }: TabProps) {
  const [f, setF] = useState({ port: '', protocol: 'tcp', to_port: '', to_addr: '' })
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Masquerading &amp; forwarding</CardTitle>
        </CardHeader>
        <CardContent className="divide-y">
          <ToggleRow
            label="Masquerade"
            description="Source-NAT outgoing IPv4 traffic from this zone (typical for routers / NAT gateways)."
            runtime={runtime?.masquerade}
            permanent={permanent?.masquerade}
            kind="masquerade"
            ops={ops}
          />
          <ToggleRow
            label="Intra-zone forwarding"
            description="Allow packets to be forwarded between interfaces and sources within this zone."
            runtime={runtime?.forward}
            permanent={permanent?.forward}
            kind="forward"
            ops={ops}
          />
        </CardContent>
      </Card>
      <ItemList
        title="Port forwarding"
        description="Redirect incoming ports to another port and/or host. Forwarding to another host requires masquerading."
        items={mergeItems(runtime?.forward_ports, permanent?.forward_ports, fwdKey)}
        kind="forward-port"
        ops={ops}
        toValue={(p) => ({ ...p })}
        render={(p) => `${p.port}/${p.protocol} → ${p.to_addr || 'localhost'}${p.to_port ? `:${p.to_port}` : ''}`}
        addForm={
          <InlineAdd
            onSubmit={() =>
              ops.add('forward-port', f).then(() => setF({ port: '', protocol: 'tcp', to_port: '', to_addr: '' }))
            }
            disabled={!f.port || (!f.to_port && !f.to_addr)}
          >
            <Input
              className="h-8 w-28"
              placeholder="port"
              value={f.port}
              onChange={(e) => setF({ ...f, port: e.target.value })}
            />
            <ProtocolSelect value={f.protocol} onChange={(protocol) => setF({ ...f, protocol })} />
            <span className="text-sm text-muted-foreground">→</span>
            <Input
              className="h-8 w-40"
              placeholder="to address (opt.)"
              value={f.to_addr}
              onChange={(e) => setF({ ...f, to_addr: e.target.value })}
            />
            <Input
              className="h-8 w-28"
              placeholder="to port (opt.)"
              value={f.to_port}
              onChange={(e) => setF({ ...f, to_port: e.target.value })}
            />
          </InlineAdd>
        }
      />
    </div>
  )
}

function ProtocolsIcmpTab({ runtime, permanent, ops }: TabProps) {
  const icmp = useIcmpTypes()
  const [proto, setProto] = useState('')
  const [block, setBlock] = useState('')
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <ItemList
        title="Protocols"
        description="Allow entire IP protocols (e.g. gre, esp, vrrp)."
        items={mergeItems(runtime?.protocols, permanent?.protocols, (p) => p)}
        kind="protocol"
        ops={ops}
        toValue={(p) => ({ value: p })}
        render={(p) => p}
        addForm={
          <InlineAdd onSubmit={() => ops.add('protocol', { value: proto }).then(() => setProto(''))} disabled={!proto}>
            <Input
              className="h-8 w-48"
              placeholder="gre, esp, 47…"
              value={proto}
              onChange={(e) => setProto(e.target.value)}
            />
          </InlineAdd>
        }
      />
      <div className="grid gap-4">
        <Card>
          <CardContent className="pt-0">
            <ToggleRow
              label="ICMP block inversion"
              description="When on, the ICMP types listed below are the ONLY ones allowed; all others are blocked."
              runtime={runtime?.icmp_block_inversion}
              permanent={permanent?.icmp_block_inversion}
              kind="icmp-block-inversion"
              ops={ops}
            />
          </CardContent>
        </Card>
        <ItemList
          title="ICMP blocks"
          items={mergeItems(runtime?.icmp_blocks, permanent?.icmp_blocks, (p) => p)}
          kind="icmp-block"
          ops={ops}
          toValue={(p) => ({ name: p })}
          render={(p) => p}
          addForm={
            <InlineAdd
              onSubmit={() => ops.add('icmp-block', { name: block }).then(() => setBlock(''))}
              disabled={!block}
            >
              <Select value={block} onValueChange={setBlock}>
                <SelectTrigger size="sm" className="w-60" aria-label="ICMP type">
                  <SelectValue placeholder="ICMP type…" />
                </SelectTrigger>
                <SelectContent className="max-h-80">
                  {icmp.data?.map((t) => (
                    <SelectItem key={t} value={t}>
                      {t}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </InlineAdd>
          }
        />
      </div>
    </div>
  )
}

function BindingsTab({ runtime, permanent, ops }: TabProps) {
  const [iface, setIface] = useState('')
  const [source, setSource] = useState('')
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <ItemList
        title="Interfaces"
        description="Traffic arriving on these interfaces uses this zone. NetworkManager may also assign interfaces at runtime."
        items={mergeItems(runtime?.interfaces, permanent?.interfaces, (s) => s)}
        kind="interface"
        ops={ops}
        toValue={(s) => ({ name: s })}
        render={(s) => s}
        addForm={
          <InlineAdd onSubmit={() => ops.add('interface', { name: iface }).then(() => setIface(''))} disabled={!iface}>
            <Input className="h-8 w-48" placeholder="eth0" value={iface} onChange={(e) => setIface(e.target.value)} />
          </InlineAdd>
        }
      />
      <ItemList
        title="Sources"
        description="Traffic from these addresses, networks, MACs (or ipset:name) uses this zone. Sources take precedence over interfaces."
        items={mergeItems(runtime?.sources, permanent?.sources, (s) => s)}
        kind="source"
        ops={ops}
        toValue={(s) => ({ value: s })}
        render={(s) => s}
        addForm={
          <InlineAdd onSubmit={() => ops.add('source', { value: source }).then(() => setSource(''))} disabled={!source}>
            <Input
              className="h-8 w-56"
              placeholder="10.0.0.0/8 or ipset:name"
              value={source}
              onChange={(e) => setSource(e.target.value)}
            />
          </InlineAdd>
        }
      />
    </div>
  )
}

interface TabProps {
  runtime?: ZoneView
  permanent?: ZoneView
  ops: Ops
}

// -- page ----------------------------------------------------------------------------

const TARGETS = [
  { value: 'default', label: 'default (reject)' },
  { value: 'ACCEPT', label: 'ACCEPT' },
  { value: 'DROP', label: 'DROP' },
  { value: '%%REJECT%%', label: 'REJECT' },
]

export default function ZonePage() {
  const { name = '' } = useParams()
  const navigate = useNavigate()
  const zone = useZone(name)
  const status = useStatus()
  const ops = useZoneOps(name)
  const setTarget = useFwMutation(
    (target: string) => api.patch(`/zones/${encodeURIComponent(name)}`, { target }),
    'Zone target saved to permanent config — reload to apply',
  )
  const setDefault = useFwMutation(() => api.post('/default-zone', { zone: name }), `Default zone set to ${name}`)
  const del = useFwMutation(() => api.delete(`/zones/${encodeURIComponent(name)}`), `Zone ${name} deleted`)
  const reset = useFwMutation(
    () => api.post(`/zones/${encodeURIComponent(name)}/reset`),
    `Zone ${name} reset to defaults in permanent config — reload to apply`,
  )

  if (zone.isPending) return <Skeleton className="h-96 w-full" />
  if (zone.isError) return <p className="text-destructive">{zone.error.message}</p>

  const runtime = zone.data.runtime ?? undefined
  const permanent = zone.data.permanent ?? undefined
  const view = permanent ?? runtime!
  const isDefault = status.data?.default_zone === name
  const active = status.data?.active_zones[name]
  const props = { runtime, permanent, ops }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold">{name}</h1>
            {isDefault && <Badge>default</Badge>}
            {active ? <Badge variant="secondary">active</Badge> : <Badge variant="outline">inactive</Badge>}
            {!runtime && <Badge variant="outline">permanent only — reload to activate</Badge>}
            {!permanent && <Badge variant="secondary">runtime only</Badge>}
          </div>
          {view.short && view.short !== name && <p className="text-sm font-medium">{view.short}</p>}
          {view.description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{view.description}</p>}
          {active && (
            <p className="mt-2 text-xs text-muted-foreground">
              Bound to: {[...active.interfaces, ...active.sources].join(', ') || '—'}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Target</span>
            <Select
              value={permanent?.target ?? runtime?.target}
              onValueChange={(t) => setTarget.mutate(t)}
              disabled={!permanent}
            >
              <SelectTrigger size="sm" className="w-40" aria-label="Zone target">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TARGETS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          {!isDefault && runtime && (
            <Button variant="outline" size="sm" onClick={() => setDefault.mutate(undefined)}>
              <StarIcon /> Make default
            </Button>
          )}
          {permanent?.builtin && permanent.modified && (
            <ConfirmButton
              variant="outline"
              size="sm"
              destructive
              title={`Reset ${name} to defaults?`}
              description="Discards all customizations of this built-in zone in the permanent configuration (services, ports, rich rules, bindings). Reload to apply."
              confirmLabel="Reset zone"
              onConfirm={() => reset.mutate(undefined)}
            >
              <RotateCcwIcon /> Reset to defaults
            </ConfirmButton>
          )}
          {permanent && !permanent.builtin && !isDefault && (
            <ConfirmButton
              variant="outline"
              size="sm"
              destructive
              title={`Delete zone ${name}?`}
              description="Removes the zone from the permanent configuration. Reload to apply."
              confirmLabel="Delete zone"
              onConfirm={() => del.mutateAsync(undefined).then(() => navigate('/'))}
            >
              <Trash2Icon /> Delete
            </ConfirmButton>
          )}
        </div>
      </div>
      {runtime && permanent && runtime.target !== permanent.target && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Target differs: runtime {runtime.target}, permanent {permanent.target}. Reload to apply.
        </p>
      )}

      <Tabs defaultValue="rich">
        <TabsList className="flex-wrap">
          <TabsTrigger value="rich">
            Rich rules ({mergeItems(runtime?.rich_rules, permanent?.rich_rules, (r) => r.rule).length})
          </TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="protocols">Protocols &amp; ICMP</TabsTrigger>
          <TabsTrigger value="forwarding">Forwarding &amp; NAT</TabsTrigger>
          <TabsTrigger value="bindings">Interfaces &amp; sources</TabsTrigger>
        </TabsList>
        <TabsContent value="rich" className="mt-4">
          <RichRulesTab zone={name} {...props} />
        </TabsContent>
        <TabsContent value="services" className="mt-4">
          <ServicesTab {...props} />
        </TabsContent>
        <TabsContent value="ports" className="mt-4 grid gap-4 lg:grid-cols-2">
          <PortListTab
            {...props}
            kind="port"
            field="ports"
            title="Ports"
            description="Destination ports open in this zone."
          />
          <PortListTab
            {...props}
            kind="source-port"
            field="source_ports"
            title="Source ports"
            description="Allow traffic originating from these source ports."
          />
        </TabsContent>
        <TabsContent value="protocols" className="mt-4">
          <ProtocolsIcmpTab {...props} />
        </TabsContent>
        <TabsContent value="forwarding" className="mt-4">
          <ForwardingTab {...props} />
        </TabsContent>
        <TabsContent value="bindings" className="mt-4">
          <BindingsTab {...props} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
