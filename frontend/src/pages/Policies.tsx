import { PlusIcon } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router'
import { api } from '@/api/client'
import { useFwMutation, usePolicies, useZones } from '@/api/hooks'
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

const zoneChip = (z: string) => (
  <Badge key={z} variant={z === 'ANY' || z === 'HOST' ? 'secondary' : 'outline'} className="font-mono">
    {z}
  </Badge>
)

function ZonePicker({ label, value, onChange, names }: { label: string; value: string[]; onChange: (v: string[]) => void; names: string[] }) {
  return (
    <div className="grid gap-1.5">
      <Label>{label}</Label>
      <div className="flex max-h-40 flex-wrap gap-x-4 gap-y-2 overflow-y-auto rounded-md border p-2">
        {names.map((n) => (
          <label key={n} className="flex items-center gap-1.5 text-sm">
            <Checkbox
              checked={value.includes(n)}
              onCheckedChange={(c) => onChange(c ? [...value, n] : value.filter((x) => x !== n))}
            />
            <span className={n === 'ANY' || n === 'HOST' ? 'font-semibold' : 'font-mono'}>{n}</span>
          </label>
        ))}
      </div>
    </div>
  )
}

function NewPolicyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const zones = useZones()
  const names = ['ANY', 'HOST', ...(zones.data?.map((z) => z.name) ?? [])]
  const empty = { name: '', ingress_zones: [] as string[], egress_zones: [] as string[], target: 'CONTINUE', priority: '-1', short: '', description: '' }
  const [f, setF] = useState(empty)
  const create = useFwMutation(
    () => api.post('/policies', { ...f, priority: Number(f.priority) }),
    'Policy created — reload to activate it',
  )
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>New policy</DialogTitle>
          <DialogDescription>
            Policies filter traffic between zones (forwarded traffic), or to/from this host via HOST. Created in permanent config.
          </DialogDescription>
        </DialogHeader>
        <form
          id="new-policy"
          className="grid gap-3"
          onSubmit={(e) => {
            e.preventDefault()
            create.mutateAsync(undefined).then(() => {
              onOpenChange(false)
              setF(empty)
            }, () => {})
          }}
        >
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label htmlFor="pn">Name</Label>
              <Input id="pn" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} required pattern="[A-Za-z0-9_+\-]{1,17}" />
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="ps">Short description</Label>
              <Input id="ps" value={f.short} onChange={(e) => setF({ ...f, short: e.target.value })} />
            </div>
          </div>
          <ZonePicker label="Ingress zones (from)" value={f.ingress_zones} onChange={(v) => setF({ ...f, ingress_zones: v })} names={names} />
          <ZonePicker label="Egress zones (to)" value={f.egress_zones} onChange={(v) => setF({ ...f, egress_zones: v })} names={names} />
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>Target (when no rule matches)</Label>
              <Select value={f.target} onValueChange={(target) => setF({ ...f, target })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {['CONTINUE', 'ACCEPT', 'REJECT', 'DROP'].map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="pp">Priority (negative = before zones)</Label>
              <Input id="pp" type="number" value={f.priority} onChange={(e) => setF({ ...f, priority: e.target.value })} />
            </div>
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" form="new-policy" disabled={create.isPending || !f.ingress_zones.length || !f.egress_zones.length}>
            Create policy
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function PoliciesPage() {
  const policies = usePolicies()
  const [open, setOpen] = useState(false)
  if (policies.isPending) return <Skeleton className="h-96 w-full" />
  if (policies.isError) return <p className="text-destructive">{policies.error.message}</p>
  return (
    <Card>
      <CardHeader>
        <CardTitle>Policies</CardTitle>
        <CardDescription>
          Zone-to-zone rules (firewalld ≥ 1.0). Use them for routing/forwarding between zones, container networks, or
          traffic to/from this host (HOST). Lower priority runs first; negative priorities run before zone rules.
        </CardDescription>
        <CardAction>
          <Button size="sm" onClick={() => setOpen(true)}><PlusIcon /> New policy</Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Policy</TableHead>
              <TableHead>From</TableHead>
              <TableHead>To</TableHead>
              <TableHead className="w-20">Priority</TableHead>
              <TableHead className="w-24">Target</TableHead>
              <TableHead>Status</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {policies.data.map((p) => (
              <TableRow key={p.name}>
                <TableCell>
                  <Link to={`/policies/${encodeURIComponent(p.name)}`} className="font-medium hover:underline">{p.name}</Link>
                  {p.short && <div className="text-xs text-muted-foreground">{p.short}</div>}
                </TableCell>
                <TableCell className="space-x-1">{p.ingress_zones.map(zoneChip)}</TableCell>
                <TableCell className="space-x-1">{p.egress_zones.map(zoneChip)}</TableCell>
                <TableCell className="tabular-nums">{p.priority}</TableCell>
                <TableCell>{p.target}</TableCell>
                <TableCell className="space-x-1">
                  {p.active && <Badge variant="secondary">active</Badge>}
                  {p.disable && <Badge variant="outline">disabled</Badge>}
                  {!p.runtime && <Badge variant="outline">needs reload</Badge>}
                </TableCell>
              </TableRow>
            ))}
            {policies.data.length === 0 && (
              <TableRow><TableCell colSpan={6} className="text-center text-muted-foreground">No policies</TableCell></TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
      <NewPolicyDialog open={open} onOpenChange={setOpen} />
    </Card>
  )
}
