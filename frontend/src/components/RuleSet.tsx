import { ArrowRightLeftIcon, CopyIcon, FileCode2Icon, ListPlusIcon, PencilIcon, PlusIcon, Trash2Icon } from 'lucide-react'
import { useMemo, useState, type FormEvent, type ReactNode } from 'react'
import { toast } from 'sonner'
import { useIcmpTypes, usePolicies, useServices, useZones } from '@/api/hooks'
import type { ForwardPortSpec, OpKind, PortSpec, RichRule, Scope, Target, ZoneView, PolicyView } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { ExportCodeDialog, type ExportScope } from '@/components/ExportCode'
import { api } from '@/api/client'
import { Textarea } from '@/components/ui/textarea'
import { PresenceBadge } from '@/components/PresenceBadge'
import { RichRuleBuilder, type RuleSubmit } from '@/components/RichRuleBuilder'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { describe } from '@/lib/rule-form'
import { useCanEdit } from '@/lib/session'
import { mergeItems, removalTarget, type Merged, type Presence, type RuleOps } from '@/lib/zone-ops'

const PROTOCOLS = ['tcp', 'udp', 'sctp', 'dccp']
export const portKey = (p: PortSpec) => `${p.port}/${p.protocol}`
const fwdKey = (p: ForwardPortSpec) => `${p.port}/${p.protocol}>${p.to_addr}:${p.to_port}`

type View = Partial<ZoneView> & Partial<PolicyView>

export interface TabProps {
  runtime?: View
  permanent?: View
  ops: RuleOps
}

// -- selection & bulk transfer --------------------------------------------------------

function useSelection() {
  const [sel, setSel] = useState<Set<string>>(new Set())
  return {
    sel,
    has: (k: string) => sel.has(k),
    toggle: (k: string) =>
      setSel((s) => {
        const n = new Set(s)
        if (n.has(k)) n.delete(k)
        else n.add(k)
        return n
      }),
    setAll: (keys: string[], on: boolean) => setSel(on ? new Set(keys) : new Set()),
    clear: () => setSel(new Set()),
  }
}

interface Destination {
  scope: Scope
  name: string
}

function TransferDialog({
  open,
  onOpenChange,
  count,
  current,
  onSubmit,
}: {
  open: boolean
  onOpenChange: (o: boolean) => void
  count: number
  current: Destination
  onSubmit: (dest: Destination, move: boolean) => Promise<unknown>
}) {
  const zones = useZones()
  const policies = usePolicies()
  const [dest, setDest] = useState('')
  const [move, setMove] = useState(false)
  const [busy, setBusy] = useState(false)
  const value = (d: Destination) => `${d.scope}:${d.name}`
  async function submit() {
    const [scope, ...rest] = dest.split(':')
    setBusy(true)
    try {
      await onSubmit({ scope: scope as Scope, name: rest.join(':') }, move)
      onOpenChange(false)
    } catch {
      /* toast shown */
    } finally {
      setBusy(false)
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Copy or move {count} item{count === 1 ? '' : 's'}</DialogTitle>
          <DialogDescription>Items are added to the destination using the current apply mode.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <Select value={dest} onValueChange={setDest}>
            <SelectTrigger className="w-full" aria-label="Destination">
              <SelectValue placeholder="Destination zone or policy…" />
            </SelectTrigger>
            <SelectContent className="max-h-80">
              <SelectGroup>
                <SelectLabel>Zones</SelectLabel>
                {zones.data
                  ?.filter((z) => !(current.scope === 'zone' && z.name === current.name))
                  .map((z) => (
                    <SelectItem key={z.name} value={value({ scope: 'zone', name: z.name })}>
                      {z.name}
                    </SelectItem>
                  ))}
              </SelectGroup>
              <SelectGroup>
                <SelectLabel>Policies</SelectLabel>
                {policies.data
                  ?.filter((p) => !(current.scope === 'policy' && p.name === current.name))
                  .map((p) => (
                    <SelectItem key={p.name} value={value({ scope: 'policy', name: p.name })}>
                      {p.name}
                    </SelectItem>
                  ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={move} onCheckedChange={setMove} /> Move (remove from {current.name})
          </label>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={submit} disabled={!dest || busy}>
            {move ? 'Move' : 'Copy'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

/** Bulk operations over selected items of one kind. */
function useBulk<T>(ops: RuleOps, kind: OpKind, toValue: (t: T) => Record<string, string>) {
  const target = ops.target
  /** Group items by where their removal applies so each batch is valid, then run the batches. */
  async function byTarget(items: Merged<T>[], build: (group: Merged<T>[], t: Target) => ReturnType<RuleOps['op']>[]) {
    const groups = new Map<Target, Merged<T>[]>()
    for (const m of items) {
      const t = removalTarget(m, target)
      if (!t) continue
      groups.set(t, [...(groups.get(t) ?? []), m])
    }
    for (const [t, group] of groups) await ops.run(build(group, t), t)
  }
  return {
    remove: (items: Merged<T>[]) => byTarget(items, (g) => g.map((m) => ops.op('remove', kind, toValue(m.item)))),
    transfer: async (items: Merged<T>[], dest: Destination, move: boolean) => {
      if (!move) return ops.run(items.map((m) => ops.op('add', kind, toValue(m.item), dest.name, dest.scope)))
      return byTarget(items, (g) => [
        ...g.map((m) => ops.op('add', kind, toValue(m.item), dest.name, dest.scope)),
        ...g.map((m) => ops.op('remove', kind, toValue(m.item))),
      ])
    },
    /** Make runtime-only items permanent and vice versa. */
    sync: (items: Merged<T>[]) => {
      const toPerm = items.filter((m) => m.runtime && !m.permanent)
      const toRt = items.filter((m) => m.permanent && !m.runtime)
      return (async () => {
        if (toPerm.length) await ops.run(toPerm.map((m) => ops.op('add', kind, toValue(m.item))), 'permanent')
        if (toRt.length) await ops.run(toRt.map((m) => ops.op('add', kind, toValue(m.item))), 'runtime')
      })()
    },
    /** Remove only the runtime copy (e.g. revert an unsaved change). */
    dropRuntime: (items: Merged<T>[]) => {
      const rt = items.filter((m) => m.runtime)
      return rt.length ? ops.run(rt.map((m) => ops.op('remove', kind, toValue(m.item))), 'runtime') : Promise.resolve()
    },
  }
}

function BulkBar<T>({
  selected,
  bulk,
  onTransfer,
  onClear,
  extra,
}: {
  selected: Merged<T>[]
  bulk: ReturnType<typeof useBulk<T>>
  onTransfer: () => void
  onClear: () => void
  extra?: ReactNode
}) {
  const canEdit = useCanEdit()
  if (selected.length === 0 || !canEdit) return null
  const unsynced = selected.some((m) => m.runtime !== m.permanent)
  const done = (p: Promise<unknown>) => p.then(onClear, () => {})
  return (
    <div className="flex flex-wrap items-center gap-2 rounded-md border bg-muted/50 px-3 py-2 text-sm">
      <span className="font-medium">{selected.length} selected</span>
      <ConfirmButton
        size="sm"
        variant="outline"
        destructive
        title={`Delete ${selected.length} item${selected.length === 1 ? '' : 's'}?`}
        confirmLabel="Delete"
        onConfirm={() => done(bulk.remove(selected))}
      >
        <Trash2Icon /> Delete
      </ConfirmButton>
      <Button size="sm" variant="outline" onClick={onTransfer}>
        <CopyIcon /> Copy / move…
      </Button>
      {unsynced && (
        <Button size="sm" variant="outline" onClick={() => done(bulk.sync(selected))}>
          <ArrowRightLeftIcon /> Sync runtime ↔ permanent
        </Button>
      )}
      {selected.some((m) => m.runtime) && (
        <ConfirmButton
          size="sm"
          variant="outline"
          title="Remove from runtime only?"
          description="The permanent configuration is untouched; items only in permanent config are skipped."
          onConfirm={() => done(bulk.dropRuntime(selected))}
        >
          Remove from runtime
        </ConfirmButton>
      )}
      {extra}
      <Button size="sm" variant="ghost" className="ml-auto" onClick={onClear}>
        Clear
      </Button>
    </div>
  )
}

// -- rich rules -------------------------------------------------------------------------

type RuleEntry = { rule: string; parsed: RichRule | null }

export interface RuleDraft {
  rule: string
  parsed: RichRule | null
}

export function RichRulesCard({
  runtime,
  permanent,
  ops,
  draft,
  onDraftConsumed,
}: TabProps & { draft?: RuleDraft | null; onDraftConsumed?: () => void }) {
  const rules = useMemo(
    () =>
      mergeItems(runtime?.rich_rules, permanent?.rich_rules, (r) => r.rule).sort(
        (a, b) => (a.item.parsed?.priority ?? 0) - (b.item.parsed?.priority ?? 0),
      ),
    [runtime, permanent],
  )
  const [dialog, setDialog] = useState<{ mode: 'add' | 'edit' | 'dup'; entry?: Merged<RuleEntry>; draft?: RuleDraft } | null>(
    draft ? { mode: 'add', draft } : null,
  )
  const [filter, setFilter] = useState('')
  const [transfer, setTransfer] = useState(false)
  const [exportScope, setExportScope] = useState<ExportScope | null>(null)
  const [bulkImport, setBulkImport] = useState(false)
  const selection = useSelection()
  const bulk = useBulk<RuleEntry>(ops, 'rich-rule', (r) => ({ rule: r.rule }))
  const canEdit = useCanEdit()
  const shown = rules.filter((r) => r.item.rule.toLowerCase().includes(filter.toLowerCase()))
  const selected = rules.filter((r) => selection.has(r.key))

  async function submit({ rule, timeout }: RuleSubmit) {
    if (dialog?.mode === 'edit' && dialog.entry) {
      const old = dialog.entry
      if (old.item.rule === rule) return
      const where = removalTarget(old, ops.target)
      if (!where) throw new Error('Rule is not present in the selected configuration')
      // Remove + add in one atomic batch so a failed add restores the old rule.
      await ops.run([ops.op('remove', 'rich-rule', { rule: old.item.rule }), ops.op('add', 'rich-rule', { rule })], where)
    } else {
      await ops.add('rich-rule', { rule }, { timeout })
    }
  }

  const initial = dialog?.draft ?? dialog?.entry?.item
  return (
    <Card>
      <CardHeader>
        <CardTitle>Rich rules</CardTitle>
        <CardDescription>
          Evaluated by priority (lowest first). Priority-0 rules run in the order log → deny → allow, alongside services
          and ports.
        </CardDescription>
        <CardAction className="flex gap-2">
          <Input placeholder="Filter…" value={filter} onChange={(e) => setFilter(e.target.value)} className="h-8 w-40" />
          {canEdit && (
            <Button size="sm" variant="outline" onClick={() => setBulkImport(true)}>
              <ListPlusIcon /> Import IP list
            </Button>
          )}
          {canEdit && (
            <Button size="sm" onClick={() => setDialog({ mode: 'add' })}>
              <PlusIcon /> Add rule
            </Button>
          )}
        </CardAction>
      </CardHeader>
      <CardContent className="grid gap-3">
        <BulkBar
          selected={selected}
          bulk={bulk}
          onTransfer={() => setTransfer(true)}
          onClear={selection.clear}
          extra={
            <Button size="sm" variant="outline"
              onClick={() => setExportScope({ rules: selected.map((r) => r.item.rule), scope: ops.scope, name: ops.name })}>
              <FileCode2Icon /> Ansible / Bash
            </Button>
          }
        />
        {rules.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">No rich rules in {ops.name}.</p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8">
                  <Checkbox
                    disabled={!canEdit}
                    aria-label="Select all"
                    checked={shown.length > 0 && shown.every((r) => selection.has(r.key))}
                    onCheckedChange={(c) => selection.setAll(shown.map((r) => r.key), c === true)}
                  />
                </TableHead>
                <TableHead className="w-12">Prio</TableHead>
                <TableHead className="w-14">Family</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Match</TableHead>
                <TableHead>Action</TableHead>
                <TableHead className="w-32" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {shown.map((r) => {
                const d = r.item.parsed ? describe(r.item.parsed) : null
                const action = r.item.parsed?.action?.type
                return (
                  <TableRow key={r.key} className="align-top" data-state={selection.has(r.key) ? 'selected' : undefined}>
                    <TableCell>
                      <Checkbox aria-label="Select rule" disabled={!canEdit} checked={selection.has(r.key)} onCheckedChange={() => selection.toggle(r.key)} />
                    </TableCell>
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
                              action === 'accept' ? 'default' : action === 'drop' || action === 'reject' ? 'destructive' : 'secondary'
                            }
                          >
                            {d.action}
                          </Badge>
                          <div className="mt-1">
                            <PresenceBadge where={r} onSync={() => ops.sync('rich-rule', { rule: r.item.rule }, r).catch(() => {})} />
                          </div>
                        </TableCell>
                      </>
                    ) : (
                      <TableCell colSpan={6} className="font-mono text-xs">
                        {r.item.rule}
                      </TableCell>
                    )}
                    <TableCell className="text-right whitespace-nowrap">
                      {canEdit && <>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label="Edit" onClick={() => setDialog({ mode: 'edit', entry: r })}>
                            <PencilIcon />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Edit</TooltipContent>
                      </Tooltip>
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label="Duplicate" onClick={() => setDialog({ mode: 'dup', entry: r })}>
                            <CopyIcon />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Duplicate</TooltipContent>
                      </Tooltip>
                      </>}
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
          <details className="text-xs">
            <summary className="cursor-pointer text-muted-foreground">Show raw rules</summary>
            <pre className="mt-2 overflow-x-auto rounded-md bg-muted p-3">{rules.map((r) => r.item.rule).join('\n')}</pre>
          </details>
        )}
      </CardContent>
      {dialog && (
        <RichRuleBuilder
          key={`${dialog.mode}:${dialog.entry?.key ?? dialog.draft?.rule ?? ''}`}
          open
          onOpenChange={(o) => {
            if (!o) {
              setDialog(null)
              onDraftConsumed?.()
            }
          }}
          initial={initial}
          title={dialog.mode === 'edit' ? 'Edit rich rule' : 'New rich rule'}
          submitLabel={dialog.mode === 'edit' ? 'Save' : 'Add rule'}
          allowTimeout={dialog.mode !== 'edit' && ops.scope === 'zone'}
          onSubmit={submit}
          ddnsTarget={dialog.mode === 'edit' ? undefined : { zone: ops.name, scope: ops.scope }}
        />
      )}
      {exportScope && (
        <ExportCodeDialog title={`${exportScope.rules?.length} rich rule(s) from ${ops.name}`} scope={exportScope} onClose={() => setExportScope(null)} />
      )}
      {bulkImport && <BulkIpRulesDialog ops={ops} onClose={() => setBulkImport(false)} />}
      <TransferDialog
        open={transfer}
        onOpenChange={setTransfer}
        count={selected.length}
        current={{ scope: ops.scope, name: ops.name }}
        onSubmit={(dest, move) => bulk.transfer(selected, dest, move).then(selection.clear)}
      />
    </Card>
  )
}

/** Upload/paste a .txt or .csv of addresses and generate one rich rule per address. */
function BulkIpRulesDialog({ ops, onClose }: { ops: RuleOps; onClose: () => void }) {
  const services = useServices()
  const [text, setText] = useState('')
  const [action, setAction] = useState<'drop' | 'reject' | 'accept'>('drop')
  const [match, setMatch] = useState<'all' | 'service' | 'port'>('all')
  const [service, setService] = useState('ssh')
  const [port, setPort] = useState('')
  const [protocol, setProtocol] = useState('tcp')
  const [preview, setPreview] = useState<{ rules: string[]; invalid: string[] } | null>(null)
  const [busy, setBusy] = useState(false)
  const body = (p: boolean) => ({
    text, zone: ops.name, scope: ops.scope, action, target: ops.target, preview: p,
    service: match === 'service' ? service : '', port: match === 'port' ? port : '', protocol,
    priority: action === 'accept' ? 0 : -100,
  })
  async function doPreview() {
    setBusy(true)
    try {
      setPreview(await api.post<{ rules: string[]; invalid: string[] }>('/bulk/rules', body(true)))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }
  async function apply() {
    if (!preview) return
    // Same lock-out check and apply path as any other change.
    try {
      await ops.run(preview.rules.map((rule) => ops.op('add', 'rich-rule', { rule })))
      onClose()
    } catch {
      /* toast shown */
    }
  }
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[92svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>Import IP list into {ops.name}</DialogTitle>
          <DialogDescription>
            Paste addresses or upload a .txt / .csv file — addresses are found in any column, headers and comments are
            ignored. One rich rule is created per address. For long lists, an IP set (IP Sets → Bulk add) is faster.
          </DialogDescription>
        </DialogHeader>
        <Textarea rows={7} className="font-mono text-xs" value={text} placeholder={'203.0.113.7\n198.51.100.0/24\nip,comment\n192.0.2.9,scanner'}
          onChange={(e) => { setText(e.target.value); setPreview(null) }} />
        <input type="file" accept=".txt,.csv,.tsv,.list,text/plain,text/csv" className="text-sm"
          onChange={(e) => e.target.files?.[0]?.text().then((t) => { setText(t); setPreview(null) })} />
        <div className="flex flex-wrap items-center gap-2">
          <Select value={action} onValueChange={(v) => { setAction(v as typeof action); setPreview(null) }}>
            <SelectTrigger size="sm" className="w-32" aria-label="Action"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="drop">Drop</SelectItem>
              <SelectItem value="reject">Reject</SelectItem>
              <SelectItem value="accept">Accept</SelectItem>
            </SelectContent>
          </Select>
          <Select value={match} onValueChange={(v) => { setMatch(v as typeof match); setPreview(null) }}>
            <SelectTrigger size="sm" className="w-40" aria-label="Match"><SelectValue /></SelectTrigger>
            <SelectContent>
              <SelectItem value="all">all traffic</SelectItem>
              <SelectItem value="service">a service</SelectItem>
              <SelectItem value="port">a port</SelectItem>
            </SelectContent>
          </Select>
          {match === 'service' && (
            <Select value={service} onValueChange={(v) => { setService(v); setPreview(null) }}>
              <SelectTrigger size="sm" className="w-44" aria-label="Service"><SelectValue /></SelectTrigger>
              <SelectContent className="max-h-72">{services.data?.map((x) => <SelectItem key={x.name} value={x.name}>{x.name}</SelectItem>)}</SelectContent>
            </Select>
          )}
          {match === 'port' && (
            <>
              <Input className="h-8 w-28" placeholder="port" value={port} onChange={(e) => { setPort(e.target.value); setPreview(null) }} />
              <ProtocolSelect value={protocol} onChange={(v) => { setProtocol(v); setPreview(null) }} />
            </>
          )}
        </div>
        {preview && (
          <div className="grid gap-1 rounded-md border bg-muted/40 p-3 text-xs">
            <div className="font-sans text-sm font-medium">{preview.rules.length} rule(s){preview.invalid.length ? `, ${preview.invalid.length} invalid skipped (${preview.invalid.slice(0, 3).join(', ')})` : ''}</div>
            <pre className="max-h-48 overflow-auto">{preview.rules.slice(0, 200).join('\n')}{preview.rules.length > 200 ? `\n… ${preview.rules.length - 200} more` : ''}</pre>
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          {preview ? (
            <Button onClick={apply} disabled={!preview.rules.length || ops.pending}>Add {preview.rules.length} rules</Button>
          ) : (
            <Button onClick={doPreview} disabled={!text.trim() || busy || (match === 'port' && !port)}>Preview</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// -- generic item lists --------------------------------------------------------------

export function ItemList<T>({
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
  ops: RuleOps
  addForm?: ReactNode
  empty?: string
}) {
  const selection = useSelection()
  const canEdit = useCanEdit()
  const bulk = useBulk<T>(ops, kind, toValue)
  const [transfer, setTransfer] = useState(false)
  const selected = items.filter((m) => selection.has(m.key))
  const transferable = !['interface', 'source', 'ingress-zone', 'egress-zone'].includes(kind)
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        {description && <CardDescription>{description}</CardDescription>}
      </CardHeader>
      <CardContent className="grid gap-3">
        {canEdit && addForm}
        {transferable ? (
          <BulkBar selected={selected} bulk={bulk} onTransfer={() => setTransfer(true)} onClear={selection.clear} />
        ) : (
          selected.length > 0 && (
            <div className="flex items-center gap-2 rounded-md border bg-muted/50 px-3 py-2 text-sm">
              <span className="font-medium">{selected.length} selected</span>
              <ConfirmButton size="sm" variant="outline" destructive title={`Remove ${selected.length}?`} confirmLabel="Remove"
                onConfirm={() => bulk.remove(selected).then(selection.clear, () => {})}>
                <Trash2Icon /> Remove
              </ConfirmButton>
            </div>
          )
        )}
        {items.length === 0 ? (
          <p className="text-sm text-muted-foreground">{empty}</p>
        ) : (
          <ul className="divide-y rounded-md border">
            {items.map((m) => (
              <li key={m.key} className="flex items-center gap-3 px-3 py-2 text-sm">
                {canEdit && <Checkbox aria-label="Select" checked={selection.has(m.key)} onCheckedChange={() => selection.toggle(m.key)} />}
                <span className="min-w-0 flex-1 truncate font-mono">{render(m.item)}</span>
                <PresenceBadge where={m} onSync={() => ops.sync(kind, toValue(m.item), m).catch(() => {})} />
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
      {transferable && (
        <TransferDialog
          open={transfer}
          onOpenChange={setTransfer}
          count={selected.length}
          current={{ scope: ops.scope, name: ops.name }}
          onSubmit={(dest, move) => bulk.transfer(selected, dest, move).then(selection.clear)}
        />
      )}
    </Card>
  )
}

export function InlineAdd({ children, onSubmit, disabled }: { children: ReactNode; onSubmit: () => Promise<unknown>; disabled?: boolean }) {
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

export function ProtocolSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
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

export function ServicesTab({ runtime, permanent, ops }: TabProps) {
  const services = useServices()
  const [name, setName] = useState('')
  const items = mergeItems(runtime?.services, permanent?.services, (s) => s)
  const byName = new Map(services.data?.map((s) => [s.name, s]))
  const available = services.data?.filter((s) => !items.some((i) => i.key === s.name)) ?? []
  return (
    <ItemList
      title="Services"
      description={ops.scope === 'zone' ? 'Predefined services allowed into this zone.' : 'Services this policy allows.'}
      items={items}
      kind="service"
      ops={ops}
      toValue={(s) => ({ name: s })}
      render={(s) => (
        <span>
          {s}{' '}
          <span className="font-sans text-xs text-muted-foreground">{byName.get(s)?.ports.map(portKey).join(', ')}</span>
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
                <SelectItem key={s.name} value={s.name} disabled={!s.runtime && ops.target !== 'permanent'}>
                  {s.name}
                  {s.short && s.short !== s.name && <span className="text-muted-foreground"> — {s.short}</span>}
                  {!s.runtime && <span className="text-muted-foreground"> (reload first)</span>}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </InlineAdd>
      }
    />
  )
}

export function PortsTab({ runtime, permanent, ops }: TabProps) {
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <PortList {...{ runtime, permanent, ops }} kind="port" field="ports" title="Ports" description="Destination ports allowed." />
      <PortList
        {...{ runtime, permanent, ops }}
        kind="source-port"
        field="source_ports"
        title="Source ports"
        description="Allow traffic originating from these source ports."
      />
    </div>
  )
}

function PortList({
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
          <Input className="h-8 w-40" placeholder="port or 1000-2000" value={port} onChange={(e) => setPort(e.target.value)} />
          <ProtocolSelect value={protocol} onChange={setProtocol} />
        </InlineAdd>
      }
    />
  )
}

export function ToggleRow({
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
  ops: RuleOps
}) {
  const where: Presence = { runtime: !!runtime, permanent: !!permanent }
  const on =
    ops.target === 'runtime' ? where.runtime : ops.target === 'permanent' ? where.permanent : where.runtime && where.permanent
  const differs = where.runtime !== where.permanent
  const canEdit = useCanEdit()
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
        disabled={!canEdit}
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

export function ForwardingTab({ runtime, permanent, ops }: TabProps) {
  const [f, setF] = useState({ port: '', protocol: 'tcp', to_port: '', to_addr: '' })
  return (
    <div className="grid gap-4">
      <Card>
        <CardHeader>
          <CardTitle>Masquerading{ops.scope === 'zone' ? ' & forwarding' : ''}</CardTitle>
        </CardHeader>
        <CardContent className="divide-y">
          <ToggleRow
            label="Masquerade"
            description="Source-NAT traffic leaving through this zone/policy (typical for routers / NAT gateways)."
            runtime={runtime?.masquerade}
            permanent={permanent?.masquerade}
            kind="masquerade"
            ops={ops}
          />
          {ops.scope === 'zone' && (
            <ToggleRow
              label="Intra-zone forwarding"
              description="Allow packets to be forwarded between interfaces and sources within this zone."
              runtime={runtime?.forward}
              permanent={permanent?.forward}
              kind="forward"
              ops={ops}
            />
          )}
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
            onSubmit={() => ops.add('forward-port', f).then(() => setF({ port: '', protocol: 'tcp', to_port: '', to_addr: '' }))}
            disabled={!f.port || (!f.to_port && !f.to_addr)}
          >
            <Input className="h-8 w-28" placeholder="port" value={f.port} onChange={(e) => setF({ ...f, port: e.target.value })} />
            <ProtocolSelect value={f.protocol} onChange={(protocol) => setF({ ...f, protocol })} />
            <span className="text-sm text-muted-foreground">→</span>
            <Input className="h-8 w-40" placeholder="to address (opt.)" value={f.to_addr} onChange={(e) => setF({ ...f, to_addr: e.target.value })} />
            <Input className="h-8 w-28" placeholder="to port (opt.)" value={f.to_port} onChange={(e) => setF({ ...f, to_port: e.target.value })} />
          </InlineAdd>
        }
      />
    </div>
  )
}

export function ProtocolsIcmpTab({ runtime, permanent, ops }: TabProps) {
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
            <Input className="h-8 w-48" placeholder="gre, esp, 47…" value={proto} onChange={(e) => setProto(e.target.value)} />
          </InlineAdd>
        }
      />
      <div className="grid gap-4">
        {ops.scope === 'zone' && (
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
        )}
        <ItemList
          title="ICMP blocks"
          items={mergeItems(runtime?.icmp_blocks, permanent?.icmp_blocks, (p) => p)}
          kind="icmp-block"
          ops={ops}
          toValue={(p) => ({ name: p })}
          render={(p) => p}
          addForm={
            <InlineAdd onSubmit={() => ops.add('icmp-block', { name: block }).then(() => setBlock(''))} disabled={!block}>
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

export function BindingsTab({ runtime, permanent, ops }: TabProps) {
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
            <Input className="h-8 w-56" placeholder="10.0.0.0/8 or ipset:name" value={source} onChange={(e) => setSource(e.target.value)} />
          </InlineAdd>
        }
      />
    </div>
  )
}

/** Ingress/egress zone lists of a policy. */
export function PolicyZonesTab({ runtime, permanent, ops }: TabProps) {
  const zones = useZones()
  const special = ['ANY', 'HOST']
  const names = [...special, ...(zones.data?.map((z) => z.name) ?? [])]
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      {(['ingress', 'egress'] as const).map((dir) => (
        <ZoneListEditor
          key={dir}
          dir={dir}
          names={names}
          items={mergeItems(runtime?.[`${dir}_zones`], permanent?.[`${dir}_zones`], (s) => s)}
          ops={ops}
        />
      ))}
    </div>
  )
}

function ZoneListEditor({ dir, names, items, ops }: { dir: 'ingress' | 'egress'; names: string[]; items: Merged<string>[]; ops: RuleOps }) {
  const [name, setName] = useState('')
  const kind: OpKind = dir === 'ingress' ? 'ingress-zone' : 'egress-zone'
  return (
    <ItemList
      title={dir === 'ingress' ? 'Ingress zones (traffic from)' : 'Egress zones (traffic to)'}
      description={
        dir === 'ingress'
          ? 'Where packets come from. HOST = this machine (outgoing), ANY = every zone.'
          : 'Where packets go. HOST = this machine (incoming), ANY = every zone.'
      }
      items={items}
      kind={kind}
      ops={ops}
      toValue={(s) => ({ name: s })}
      render={(s) => (special(s) ? <Badge variant="secondary">{s}</Badge> : s)}
      addForm={
        <InlineAdd onSubmit={() => ops.add(kind, { name }).then(() => setName(''))} disabled={!name}>
          <Select value={name} onValueChange={setName}>
            <SelectTrigger size="sm" className="w-56" aria-label="Zone">
              <SelectValue placeholder="Zone…" />
            </SelectTrigger>
            <SelectContent>
              {names
                .filter((n) => !items.some((i) => i.key === n))
                .map((n) => (
                  <SelectItem key={n} value={n}>
                    {n}
                  </SelectItem>
                ))}
            </SelectContent>
          </Select>
        </InlineAdd>
      }
    />
  )
}

const special = (s: string) => s === 'ANY' || s === 'HOST'

