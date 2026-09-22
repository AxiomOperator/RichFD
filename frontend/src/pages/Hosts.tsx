import { PlugZapIcon, PlusIcon, ServerIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { useFwMutation, useHosts } from '@/api/hooks'
import { ConfirmButton } from '@/components/ConfirmButton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Textarea } from '@/components/ui/textarea'
import { useHostSwitcher } from '@/lib/host'
import { useCanEdit } from '@/lib/session'

export default function HostsPage() {
  const hosts = useHosts()
  const canEdit = useCanEdit()
  const { switchTo } = useHostSwitcher()
  const empty = { name: '', url: '', token: '', verify_tls: true, ca_pem: '' }
  const [f, setF] = useState(empty)
  const add = useFwMutation(() => api.post('/hosts', f), 'Host added')
  const remove = useFwMutation((id: string) => api.delete(`/hosts/${id}`), 'Host removed')

  async function test(id: string) {
    try {
      const r = await api.post<{ ok: boolean; error?: string; version?: string; default_zone?: string }>(`/hosts/${id}/test`)
      if (r.ok) toast.success(`Connected: firewalld ${r.version}, default zone ${r.default_zone}`)
      else toast.error(r.error ?? 'Failed')
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Managed hosts</CardTitle>
          <CardDescription>
            This richrule instance can act as a console for other hosts running richrule. On each remote host, create an
            agent token (Settings → Agent tokens) and make richrule reachable from here (RICHRULE_HOST=0.0.0.0 with TLS
            recommended). Then pick the host in the sidebar to manage it with this UI.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow><TableHead>Name</TableHead><TableHead>URL</TableHead><TableHead>TLS</TableHead><TableHead className="w-48" /></TableRow>
            </TableHeader>
            <TableBody>
              {hosts.data?.map((h) => (
                <TableRow key={h.id}>
                  <TableCell className="font-medium">{h.name}</TableCell>
                  <TableCell className="font-mono text-xs">{h.url}</TableCell>
                  <TableCell>
                    {!h.url.startsWith('https') ? <Badge variant="destructive">plain HTTP</Badge> : h.verify_tls ? <Badge variant="secondary">verified{h.ca_pem ? ' (custom CA)' : ''}</Badge> : <Badge variant="outline">not verified</Badge>}
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <Button size="sm" variant="ghost" onClick={() => test(h.id)}><PlugZapIcon /> Test</Button>
                    <Button size="sm" variant="ghost" onClick={() => switchTo(h.id)}><ServerIcon /> Manage</Button>
                    {canEdit && (
                      <ConfirmButton size="icon-sm" destructive aria-label="Remove" title={`Remove ${h.name}?`} confirmLabel="Remove" onConfirm={() => remove.mutate(h.id)}>
                        <Trash2Icon />
                      </ConfirmButton>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {hosts.data?.length === 0 && <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground">No remote hosts yet.</TableCell></TableRow>}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      {canEdit && (
        <Card>
          <CardHeader><CardTitle>Add host</CardTitle></CardHeader>
          <CardContent>
            <form className="grid max-w-2xl gap-3" onSubmit={(e) => {
              e.preventDefault()
              add.mutateAsync(undefined).then(() => setF(empty), () => {})
            }}>
              <div className="grid grid-cols-2 gap-3">
                <div className="grid gap-1.5">
                  <Label htmlFor="h-name">Name</Label>
                  <Input id="h-name" value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} placeholder="web-01" />
                </div>
                <div className="grid gap-1.5">
                  <Label htmlFor="h-url">URL</Label>
                  <Input id="h-url" required value={f.url} onChange={(e) => setF({ ...f, url: e.target.value })} placeholder="https://web-01.example.com:8443" />
                </div>
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="h-token">Agent token</Label>
                <Input id="h-token" required type="password" value={f.token} onChange={(e) => setF({ ...f, token: e.target.value })} placeholder="rr_…" autoComplete="off" />
              </div>
              <label className="flex items-center gap-2 text-sm">
                <Switch checked={f.verify_tls} onCheckedChange={(verify_tls) => setF({ ...f, verify_tls })} /> Verify TLS certificate
              </label>
              {f.verify_tls && (
                <div className="grid gap-1.5">
                  <Label htmlFor="h-ca">Custom CA / self-signed certificate (PEM, optional)</Label>
                  <Textarea id="h-ca" rows={3} className="font-mono text-xs" value={f.ca_pem} onChange={(e) => setF({ ...f, ca_pem: e.target.value })} placeholder="-----BEGIN CERTIFICATE-----" />
                </div>
              )}
              <div><Button type="submit" disabled={add.isPending}><PlusIcon /> Add host</Button></div>
            </form>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
