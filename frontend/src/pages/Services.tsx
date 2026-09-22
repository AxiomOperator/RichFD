import { PencilIcon, PlusIcon, RotateCcwIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { api } from '@/api/client'
import { useFwMutation, useHelpers, useServices } from '@/api/hooks'
import type { PortSpec, Service } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
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
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useCanEdit } from '@/lib/session'
import { ExportMenu } from './Zone'

const portsToText = (ports: PortSpec[]) => ports.map((p) => `${p.port}/${p.protocol}`).join(', ')
function textToPorts(text: string): PortSpec[] {
  return text
    .split(/[\s,]+/)
    .filter(Boolean)
    .map((t) => {
      const [port, protocol = 'tcp'] = t.split('/')
      return { port, protocol }
    })
}
const list = (text: string) => text.split(/[\s,]+/).filter(Boolean)

function ServiceDialog({ service, onClose }: { service: Service | 'new'; onClose: () => void }) {
  const helpers = useHelpers()
  const isNew = service === 'new'
  const s = isNew ? null : service
  const [f, setF] = useState({
    name: s?.name ?? '',
    short: s?.short ?? '',
    description: s?.description ?? '',
    ports: portsToText(s?.ports ?? []),
    protocols: (s?.protocols ?? []).join(', '),
    source_ports: portsToText(s?.source_ports ?? []),
    includes: (s?.includes ?? []).join(', '),
    helpers: s?.helpers ?? [],
    ipv4: s?.destination.ipv4 ?? '',
    ipv6: s?.destination.ipv6 ?? '',
  })
  const save = useFwMutation(
    () => {
      const body = {
        short: f.short,
        description: f.description,
        ports: textToPorts(f.ports),
        protocols: list(f.protocols),
        source_ports: textToPorts(f.source_ports),
        includes: list(f.includes),
        helpers: f.helpers,
        destination: { ...(f.ipv4 && { ipv4: f.ipv4 }), ...(f.ipv6 && { ipv6: f.ipv6 }) },
      }
      return isNew ? api.post('/services', { name: f.name, ...body }) : api.put(`/services/${encodeURIComponent(s!.name)}`, body)
    },
    isNew ? 'Service created — reload to use it at runtime' : 'Service saved — reload to apply',
  )
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[92svh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{isNew ? 'New service' : `Edit ${s!.name}`}</DialogTitle>
          <DialogDescription>
            {s?.builtin ? 'Editing a shipped service creates a local override; delete it to restore the default.' : 'Saved to the permanent configuration.'}
          </DialogDescription>
        </DialogHeader>
        <form
          id="svc"
          className="grid gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            save.mutateAsync(undefined).then(onClose, () => {})
          }}
        >
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="sn">Name</Label>
              <Input id="sn" value={f.name} disabled={!isNew} required pattern="[A-Za-z0-9_.+\-]{1,64}" onChange={(e) => setF({ ...f, name: e.target.value })} />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ss">Short name</Label>
              <Input id="ss" value={f.short} onChange={(e) => setF({ ...f, short: e.target.value })} />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sd">Description</Label>
            <Textarea id="sd" rows={2} value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="sp">Ports (e.g. 8080/tcp, 9000-9010/udp)</Label>
            <Input id="sp" value={f.ports} onChange={(e) => setF({ ...f, ports: e.target.value })} className="font-mono" />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="spr">Protocols (e.g. gre, esp)</Label>
              <Input id="spr" value={f.protocols} onChange={(e) => setF({ ...f, protocols: e.target.value })} className="font-mono" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ssp">Source ports</Label>
              <Input id="ssp" value={f.source_ports} onChange={(e) => setF({ ...f, source_ports: e.target.value })} className="font-mono" />
            </div>
          </div>
          <div className="grid gap-1.5">
            <Label>Connection-tracking helpers</Label>
            <div className="flex max-h-28 flex-wrap gap-x-4 gap-y-1.5 overflow-y-auto rounded-md border p-2">
              {helpers.data?.map((h) => (
                <label key={h} className="flex items-center gap-1.5 text-sm">
                  <Checkbox checked={f.helpers.includes(h)} onCheckedChange={(c) => setF({ ...f, helpers: c ? [...f.helpers, h] : f.helpers.filter((x) => x !== h) })} />
                  {h}
                </label>
              ))}
            </div>
          </div>
          <details>
            <summary className="cursor-pointer text-sm text-muted-foreground">Advanced: includes and destination restriction</summary>
            <div className="mt-3 grid gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="si">Include other services</Label>
                <Input id="si" value={f.includes} onChange={(e) => setF({ ...f, includes: e.target.value })} placeholder="e.g. https" />
              </div>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="d4">Only to IPv4 destination</Label>
                  <Input id="d4" value={f.ipv4} onChange={(e) => setF({ ...f, ipv4: e.target.value })} placeholder="224.0.0.251" />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="d6">Only to IPv6 destination</Label>
                  <Input id="d6" value={f.ipv6} onChange={(e) => setF({ ...f, ipv6: e.target.value })} placeholder="ff02::fb" />
                </div>
              </div>
            </div>
          </details>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button type="submit" form="svc" disabled={save.isPending}>{isNew ? 'Create' : 'Save'}</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function ServicesPage() {
  const services = useServices()
  const canEdit = useCanEdit()
  const [q, setQ] = useState('')
  const [custom, setCustom] = useState(false)
  const [editing, setEditing] = useState<Service | 'new' | null>(null)
  const del = useFwMutation((s: Service) => api.delete(`/services/${encodeURIComponent(s.name)}`), (s) =>
    s.builtin ? `${s.name} reset to defaults` : `${s.name} deleted`)
  if (services.isPending) return <Skeleton className="h-96 w-full" />
  if (services.isError) return <p className="text-destructive">{services.error.message}</p>
  const needle = q.toLowerCase()
  const rows = services.data.filter(
    (s) =>
      (!custom || !s.builtin || s.modified) &&
      (s.name.includes(needle) || s.short.toLowerCase().includes(needle) || s.ports.some((p) => `${p.port}/${p.protocol}`.includes(needle))),
  )
  return (
    <Card>
      <CardHeader>
        <CardTitle>Services</CardTitle>
        <CardDescription>
          {services.data.length} service definitions ({services.data.filter((s) => !s.builtin).length} custom). Use them in zones, policies and rich rules.
        </CardDescription>
        <CardAction className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm">
            <Checkbox checked={custom} onCheckedChange={(c) => setCustom(c === true)} /> Custom / modified only
          </label>
          <Input placeholder="Search name or port…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56" />
          {canEdit && <Button size="sm" onClick={() => setEditing('new')}><PlusIcon /> New service</Button>}
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Ports / protocols</TableHead>
              <TableHead>Description</TableHead>
              <TableHead className="w-28" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((s) => (
              <TableRow key={s.name}>
                <TableCell>
                  <span className="font-mono">{s.name}</span>{' '}
                  {!s.builtin && <Badge variant="secondary">custom</Badge>}
                  {s.builtin && s.modified && <Badge variant="outline">modified</Badge>}
                  {!s.runtime && <Badge variant="outline">needs reload</Badge>}
                </TableCell>
                <TableCell className="font-mono text-xs">
                  {[portsToText(s.ports), s.protocols.join(', '), s.helpers.length ? `helpers: ${s.helpers.join(', ')}` : '', s.includes.length ? `+ ${s.includes.join(', ')}` : '']
                    .filter(Boolean)
                    .join(' · ')}
                </TableCell>
                <TableCell className="max-w-md truncate text-xs text-muted-foreground" title={s.description}>
                  {s.short}{s.description ? ` — ${s.description}` : ''}
                </TableCell>
                <TableCell className="text-right whitespace-nowrap">
                  {canEdit && (
                    <Button variant="ghost" size="icon-sm" aria-label="Edit" onClick={() => setEditing(s)}><PencilIcon /></Button>
                  )}
                  {canEdit && (!s.builtin || s.modified) && (
                    <ConfirmButton size="icon-sm" destructive aria-label={s.builtin ? 'Reset' : 'Delete'}
                      title={s.builtin ? `Reset ${s.name} to its shipped definition?` : `Delete service ${s.name}?`}
                      description="Zones or rules that use it may fail to load. Reload to apply."
                      confirmLabel={s.builtin ? 'Reset' : 'Delete'} onConfirm={() => del.mutate(s)}>
                      {s.builtin ? <RotateCcwIcon /> : <Trash2Icon />}
                    </ConfirmButton>
                  )}
                  {(!s.builtin || s.modified) && <ExportMenu kind="service" name={s.name} />}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
      {editing && <ServiceDialog service={editing} onClose={() => setEditing(null)} />}
    </Card>
  )
}
