import { useQuery } from '@tanstack/react-query'
import { BanIcon, RotateCcwIcon, SettingsIcon, ShieldOffIcon, UnlockIcon } from 'lucide-react'
import { useState } from 'react'
import { api } from '@/api/client'
import { useFwMutation } from '@/api/hooks'
import type { Fail2banStatus, Jail } from '@/api/types'
import { StatTile } from '@/components/charts'
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
import { Switch } from '@/components/ui/switch'
import { useCanEdit } from '@/lib/session'

const fmtSeconds = (s: number | null) =>
  s === null ? '—' : s < 0 ? 'permanent' : s >= 86400 ? `${s / 86400}d` : s >= 3600 ? `${s / 3600}h` : s >= 60 ? `${s / 60}m` : `${s}s`

function JailSettingsDialog({ jail, filters, onClose }: { jail: string; filters: string[]; onClose: () => void }) {
  const detail = useQuery({ queryKey: ['f2b-jail', jail], queryFn: () => api.get<Jail>(`/fail2ban/jails/${jail}`), enabled: jail !== '' })
  const isNew = jail === ''
  const m = detail.data?.managed_settings ?? {}
  const [f, setF] = useState<Record<string, string>>({})
  const [name, setName] = useState('')
  const val = (k: string, fallback = '') => f[k] ?? m[k] ?? fallback
  const save = useFwMutation(
    () => api.put(`/fail2ban/jails/${encodeURIComponent(isNew ? name : jail)}`, {
      enabled: val('enabled', 'true'), port: val('port'), maxretry: val('maxretry', detail.data?.maxretry?.toString() ?? ''),
      findtime: val('findtime', detail.data?.findtime?.toString() ?? ''), bantime: val('bantime', detail.data?.bantime?.toString() ?? ''),
      banaction: val('banaction'), backend: val('backend'), logpath: val('logpath'), filter: val('filter'), ignoreip: val('ignoreip'),
    }),
    'Jail saved and fail2ban reloaded',
  )
  const field = (k: string, label: string, placeholder = '') => (
    <div className="grid gap-1.5">
      <Label htmlFor={`j-${k}`}>{label}</Label>
      <Input id={`j-${k}`} value={val(k)} placeholder={placeholder} onChange={(e) => setF({ ...f, [k]: e.target.value })} />
    </div>
  )
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{isNew ? 'New jail' : `Configure ${jail}`}</DialogTitle>
          <DialogDescription>
            Saved to /etc/fail2ban/jail.d/richfd-{isNew ? name || '<jail>' : jail}.local (your jail.local is never edited), then fail2ban reloads.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          {isNew && (
            <div className="grid grid-cols-2 gap-3">
              <div className="grid gap-1.5">
                <Label htmlFor="j-name">Jail name</Label>
                <Input id="j-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="nginx-http-auth" />
              </div>
              <div className="grid gap-1.5">
                <Label>Filter</Label>
                <Select value={val('filter', name)} onValueChange={(v) => setF({ ...f, filter: v })}>
                  <SelectTrigger className="w-full"><SelectValue placeholder="filter…" /></SelectTrigger>
                  <SelectContent className="max-h-72">{filters.map((x) => <SelectItem key={x} value={x}>{x}</SelectItem>)}</SelectContent>
                </Select>
              </div>
            </div>
          )}
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={val('enabled', 'true') === 'true'} onCheckedChange={(c) => setF({ ...f, enabled: c ? 'true' : 'false' })} /> Enabled
          </label>
          <div className="grid grid-cols-3 gap-3">
            {field('maxretry', 'Max retries', String(detail.data?.maxretry ?? '5'))}
            {field('findtime', 'Find time', fmtSeconds(detail.data?.findtime ?? 600))}
            {field('bantime', 'Ban time (-1 = forever)', fmtSeconds(detail.data?.bantime ?? 600))}
          </div>
          <div className="grid grid-cols-2 gap-3">
            {field('port', 'Port(s)', 'ssh or 22,2222')}
            {field('banaction', 'Ban action', 'firewallcmd-rich-rules')}
            {field('backend', 'Backend', 'systemd')}
            {field('logpath', 'Log path (if not systemd)', '/var/log/nginx/error.log')}
          </div>
          {field('ignoreip', 'Never ban (space-separated)', '127.0.0.1/8 ::1 192.168.1.0/24')}
          <p className="text-xs text-muted-foreground">
            With the fail2ban-firewalld package, bans become firewalld rich rules (banaction firewallcmd-rich-rules) and show up in this app.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => save.mutateAsync(undefined).then(onClose, () => {})} disabled={save.isPending || (isNew && !name)}>Save &amp; reload</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function JailCard({ j, onConfigure, managed }: { j: Jail; onConfigure: () => void; managed: boolean }) {
  const canEdit = useCanEdit()
  const [ip, setIp] = useState('')
  const act = useFwMutation(
    (v: { ip: string; action: 'ban' | 'unban' }) => api.post(`/fail2ban/jails/${j.name}/ban`, v),
    (v) => (v.action === 'ban' ? `Banned ${v.ip} in ${j.name}` : `Unbanned ${v.ip}`),
  )
  const reset = useFwMutation(() => api.delete(`/fail2ban/jails/${j.name}/settings`), 'Override removed; fail2ban reloaded')
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 font-mono">
          {j.name}
          {j.uses_firewalld ? <Badge variant="secondary">firewalld</Badge> : <Badge variant="outline">{j.actions.join(', ') || 'no action'}</Badge>}
          {managed && <Badge variant="outline">RichFD override</Badge>}
        </CardTitle>
        <CardDescription>
          Ban {fmtSeconds(j.bantime)} after {j.maxretry ?? '?'} failures within {fmtSeconds(j.findtime)} · {j.files || 'no log source'}
        </CardDescription>
        {canEdit && (
          <CardAction className="flex gap-1">
            <Button size="sm" variant="outline" onClick={onConfigure}><SettingsIcon /> Configure</Button>
            {managed && (
              <ConfirmButton size="sm" variant="outline" title={`Remove RichFD settings for ${j.name}?`} description="Deletes the jail.d override; the jail falls back to jail.conf / jail.local." onConfirm={() => reset.mutate(undefined)}>
                <RotateCcwIcon />
              </ConfirmButton>
            )}
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="grid gap-4">
        <div className="grid grid-cols-4 gap-2">
          <StatTile label="Failing now" value={j.currently_failed} />
          <StatTile label="Total failed" value={j.total_failed} />
          <StatTile label="Banned now" value={j.currently_banned} />
          <StatTile label="Total banned" value={j.total_banned} />
        </div>
        {canEdit && (
          <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); act.mutateAsync({ ip, action: 'ban' }).then(() => setIp(''), () => {}) }}>
            <Input className="h-8 w-56" placeholder="ban an address manually" value={ip} onChange={(e) => setIp(e.target.value)} />
            <Button size="sm" type="submit" variant="outline" disabled={!ip}><BanIcon /> Ban</Button>
          </form>
        )}
        <div>
          <div className="mb-1 text-sm font-medium">Banned addresses ({j.banned.length})</div>
          {j.banned.length === 0 ? (
            <p className="text-sm text-muted-foreground">None</p>
          ) : (
            <ul className="max-h-64 divide-y overflow-y-auto rounded-md border">
              {j.banned.map((b) => (
                <li key={b} className="flex items-center gap-2 px-3 py-1.5 font-mono text-sm">
                  <span className="flex-1">{b}</span>
                  {canEdit && (
                    <Button variant="ghost" size="sm" onClick={() => act.mutate({ ip: b, action: 'unban' })}><UnlockIcon /> Unban</Button>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>
      </CardContent>
    </Card>
  )
}

export default function Fail2banPage() {
  const canEdit = useCanEdit()
  const st = useQuery({ queryKey: ['fail2ban'], queryFn: () => api.get<Fail2banStatus>('/fail2ban'), refetchInterval: 10_000 })
  const [editing, setEditing] = useState<string | null>(null)
  if (st.isPending) return <Skeleton className="h-96 w-full" />
  if (st.isError) return <p className="text-destructive">{st.error.message}</p>
  const s = st.data
  if (!s.installed || !s.running)
    return (
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ShieldOffIcon className="size-5" /> Fail2ban is {s.installed ? 'not running' : 'not installed'}</CardTitle>
          <CardDescription>
            Fail2ban watches logs for brute-force attempts (SSH, web logins, mail) and bans the offenders; with the
            fail2ban-firewalld package the bans are firewalld rich rules.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-2 text-sm">
          {s.error && <p className="text-destructive">{s.error}</p>}
          <code className="rounded-md bg-muted p-3 text-xs">{s.hint}</code>
        </CardContent>
      </Card>
    )
  const totalBanned = s.jails.reduce((n, j) => n + j.currently_banned, 0)
  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-auto text-2xl font-semibold">Fail2ban</h1>
        <span className="text-sm text-muted-foreground">{s.version}</span>
        {canEdit && <Button size="sm" onClick={() => setEditing('')}>New jail</Button>}
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
        <StatTile label="Active jails" value={s.jails.length} />
        <StatTile label="Currently banned" value={totalBanned} />
        <StatTile label="Jails using firewalld" value={`${s.jails.filter((j) => j.uses_firewalld).length} / ${s.jails.length}`} />
      </div>
      {s.jails.length === 0 && <p className="text-sm text-muted-foreground">No jails are enabled.</p>}
      <div className="grid gap-4 xl:grid-cols-2">
        {s.jails.map((j) => (
          <JailCard key={j.name} j={j} managed={!!s.managed?.includes(j.name)} onConfigure={() => setEditing(j.name)} />
        ))}
      </div>
      {editing !== null && <JailSettingsDialog jail={editing} filters={s.filters} onClose={() => setEditing(null)} />}
    </div>
  )
}
