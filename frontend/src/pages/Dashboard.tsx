import { AlertTriangleIcon, PlusIcon } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '@/api/client'
import { useFwMutation, useStatus, useZones } from '@/api/hooks'
import { ConfirmButton } from '@/components/ConfirmButton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
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
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useCanEdit } from '@/lib/session'

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <Card className="gap-1 py-4">
      <CardHeader className="px-4">
        <CardDescription>{label}</CardDescription>
      </CardHeader>
      <CardContent className="px-4 text-lg font-semibold">{children}</CardContent>
    </Card>
  )
}

function NewZoneDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const [form, setForm] = useState({ name: '', target: 'default', short: '', description: '' })
  const create = useFwMutation(
    () => api.post('/zones', form),
    `Zone created — use Config → Reload to activate it`,
  )
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New zone</DialogTitle>
          <DialogDescription>Zones are created in the permanent configuration. Reload firewalld to activate.</DialogDescription>
        </DialogHeader>
        <form
          id="new-zone"
          className="grid gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            create.mutateAsync(undefined).then(() => {
              onOpenChange(false)
              setForm({ name: '', target: 'default', short: '', description: '' })
            }, () => {})
          }}
        >
          <div className="grid gap-1.5">
            <Label htmlFor="zn">Name</Label>
            <Input id="zn" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
              pattern="[A-Za-z0-9_+\-]{1,17}" title="Up to 17 letters, digits, _ + -" required />
          </div>
          <div className="grid gap-1.5">
            <Label>Target</Label>
            <Select value={form.target} onValueChange={(target) => setForm({ ...form, target })}>
              <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="default">default (reject)</SelectItem>
                <SelectItem value="ACCEPT">ACCEPT</SelectItem>
                <SelectItem value="DROP">DROP</SelectItem>
                <SelectItem value="%%REJECT%%">REJECT</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="zs">Short name</Label>
            <Input id="zs" value={form.short} onChange={(e) => setForm({ ...form, short: e.target.value })} />
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor="zd">Description</Label>
            <Input id="zd" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" form="new-zone" disabled={create.isPending}>Create zone</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function Dashboard() {
  const status = useStatus()
  const zones = useZones()
  const [newZone, setNewZone] = useState(false)
  const canEdit = useCanEdit()
  const panic = useFwMutation((enabled: boolean) => api.post('/panic', { enabled }), (on) => (on ? 'Panic mode ON' : 'Panic mode off'))
  const logDenied = useFwMutation((value: string) => api.post('/log-denied', { value }), 'Log-denied updated')

  if (status.isPending || zones.isPending) return <Skeleton className="h-96 w-full" />
  if (status.isError) return <p className="text-destructive">{status.error.message}</p>
  const s = status.data

  return (
    <div className="grid gap-6">
      <h1 className="text-2xl font-semibold">Dashboard</h1>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Stat label="firewalld">
          {s.state === 'RUNNING' ? <span className="text-emerald-600">● running</span> : s.state}{' '}
          <span className="text-sm font-normal text-muted-foreground">v{s.version}</span>
        </Stat>
        <Stat label="Default zone">
          <Link className="hover:underline" to={`/zones/${s.default_zone}`}>{s.default_zone}</Link>
        </Stat>
        <Stat label="Active zones">{Object.keys(s.active_zones).length}</Stat>
        <Stat label="Log denied packets">
          <Select value={s.log_denied} onValueChange={(v) => logDenied.mutate(v)} disabled={!canEdit}>
            <SelectTrigger size="sm" className="w-36" aria-label="Log denied"><SelectValue /></SelectTrigger>
            <SelectContent>
              {['off', 'all', 'unicast', 'broadcast', 'multicast'].map((v) => (
                <SelectItem key={v} value={v}>{v}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        </Stat>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Zones</CardTitle>
          <CardDescription>Active zones have interfaces or sources bound to them.</CardDescription>
          <CardAction>
            {canEdit && <Button size="sm" onClick={() => setNewZone(true)}><PlusIcon /> New zone</Button>}
          </CardAction>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Zone</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Interfaces</TableHead>
                <TableHead>Sources</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {zones.data
                ?.slice()
                .sort((a, b) => Number(b.active) - Number(a.active) || a.name.localeCompare(b.name))
                .map((z) => (
                  <TableRow key={z.name}>
                    <TableCell>
                      <Link to={`/zones/${encodeURIComponent(z.name)}`} className="font-medium hover:underline">{z.name}</Link>
                    </TableCell>
                    <TableCell className="space-x-1">
                      {z.default && <Badge>default</Badge>}
                      {z.active && <Badge variant="secondary">active</Badge>}
                      {!z.runtime && <Badge variant="outline">needs reload</Badge>}
                      {!z.permanent && <Badge variant="outline">runtime only</Badge>}
                    </TableCell>
                    <TableCell className="max-w-72 truncate font-mono text-xs">{z.interfaces.join(', ')}</TableCell>
                    <TableCell className="font-mono text-xs">{z.sources.join(', ')}</TableCell>
                  </TableRow>
                ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      <Card className="border-destructive/40">
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><AlertTriangleIcon className="size-4 text-destructive" /> Panic mode</CardTitle>
          <CardDescription>
            Drops ALL incoming and outgoing packets and kills established connections — including your session to this
            page. Only disable it from the console or via firewall-cmd --panic-off.
          </CardDescription>
          <CardAction>
            {s.panic_mode ? (
              <Button variant="outline" onClick={() => panic.mutate(false)} disabled={!canEdit}>Disable panic mode</Button>
            ) : (
              <ConfirmButton variant="destructive" destructive title="Enable panic mode?"
                description="All network traffic will be dropped immediately. You will lose access to this web UI."
                confirmLabel="Enable panic mode" onConfirm={() => panic.mutate(true)}>
                Enable panic mode
              </ConfirmButton>
            )}
          </CardAction>
        </CardHeader>
      </Card>
      <NewZoneDialog open={newZone} onOpenChange={setNewZone} />
    </div>
  )
}
