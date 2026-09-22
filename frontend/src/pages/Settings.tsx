import { CopyIcon, KeyRoundIcon, SendIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { useFwMutation, useNotificationSettings, useTokens } from '@/api/hooks'
import type { NotificationSettings } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useCanEdit, useSession } from '@/lib/session'

function Notifications() {
  const s = useNotificationSettings()
  return s.data ? <NotificationsForm initial={s.data} /> : null
}

function NotificationsForm({ initial }: { initial: NotificationSettings }) {
  const canEdit = useCanEdit()
  const [f, setF] = useState<NotificationSettings & { smtp_password?: string }>({ ...initial, smtp_password: '' })
  const save = useFwMutation(
    () => {
      const { smtp_password, smtp_password_set: _ignored, ...rest } = f
      return api.put('/settings/notifications', { ...rest, ...(smtp_password ? { smtp_password } : {}) })
    },
    'Notification settings saved',
  )
  async function test() {
    try {
      const r = await api.post<Record<string, string>>('/settings/notifications/test')
      Object.entries(r).forEach(([ch, res]) => (res === 'ok' ? toast.success(`${ch}: delivered`) : toast.error(`${ch}: ${res}`)))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }
  const field = (k: keyof typeof f, label: string, props: React.ComponentProps<typeof Input> = {}) => (
    <div className="grid gap-1.5">
      <Label htmlFor={`n-${k}`}>{label}</Label>
      <Input id={`n-${k}`} value={String(f[k] ?? '')} onChange={(e) => setF({ ...f, [k]: e.target.value })} {...props} />
    </div>
  )
  return (
    <Card>
      <CardHeader>
        <CardTitle>Change notifications</CardTitle>
        <CardDescription>
          Every change — including changes made outside richrule, detected automatically — is sent to the channels below.
        </CardDescription>
        <CardAction className="flex gap-2">
          <Button size="sm" variant="outline" onClick={test}><SendIcon /> Send test</Button>
        </CardAction>
      </CardHeader>
      <CardContent>
        <fieldset disabled={!canEdit} className="grid gap-5">
          <div className="grid gap-3 md:grid-cols-2">
            {field('webhook_url', 'Webhook URL (JSON POST; Slack/Mattermost-compatible "text")', { placeholder: 'https://hooks.example.com/…' })}
            <div className="grid gap-1.5">
              <Label>Events</Label>
              <Select value={f.events} onValueChange={(v) => setF({ ...f, events: v as 'changes' | 'all' })}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="changes">Changes (and failed logins)</SelectItem>
                  <SelectItem value="all">Everything, including successful logins</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={f.syslog} onCheckedChange={(syslog) => setF({ ...f, syslog })} /> Send to syslog (authpriv, tag "richrule")
          </label>
          <div className="grid gap-3 md:grid-cols-3">
            {field('email_to', 'Email to (comma-separated)')}
            {field('email_from', 'From address')}
            {field('smtp_host', 'SMTP server')}
            {field('smtp_port', 'SMTP port', { inputMode: 'numeric' })}
            {field('smtp_user', 'SMTP username')}
            {field('smtp_password', f.smtp_password_set ? 'SMTP password (stored; type to replace)' : 'SMTP password', { type: 'password', autoComplete: 'new-password' })}
          </div>
          <label className="flex items-center gap-2 text-sm">
            <Switch checked={f.smtp_starttls} onCheckedChange={(smtp_starttls) => setF({ ...f, smtp_starttls })} /> Use STARTTLS
          </label>
          <div>
            <Button onClick={() => save.mutate({ ...f, smtp_port: Number(f.smtp_port) } as never)} disabled={save.isPending}>Save</Button>
          </div>
        </fieldset>
      </CardContent>
    </Card>
  )
}

function AgentTokens() {
  const tokens = useTokens()
  const canEdit = useCanEdit()
  const [name, setName] = useState('')
  const [created, setCreated] = useState<string | null>(null)
  const create = useFwMutation(() => api.post<{ token: string }>('/tokens', { name }), 'Token created')
  const revoke = useFwMutation((n: string) => api.delete(`/tokens/${encodeURIComponent(n)}`), 'Token revoked')
  return (
    <Card>
      <CardHeader>
        <CardTitle>Agent tokens</CardTitle>
        <CardDescription>
          Let a richrule console on another machine manage this host. Create a token here and add this host (its URL and
          the token) on the console's Hosts page. Tokens have full admin rights; the console forwards its user's role.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {canEdit && (
          <form className="flex gap-2" onSubmit={(e) => {
            e.preventDefault()
            create.mutateAsync(undefined).then((r) => { setCreated(r.token); setName('') }, () => {})
          }}>
            <Input className="h-8 w-64" placeholder="token name (e.g. console-hq)" value={name} onChange={(e) => setName(e.target.value)} required />
            <Button size="sm" type="submit"><KeyRoundIcon /> Create token</Button>
          </form>
        )}
        {created && (
          <div className="grid gap-2 rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
            <div className="font-medium">Copy this token now — it is not shown again.</div>
            <div className="flex items-center gap-2">
              <code className="flex-1 rounded bg-background p-2 text-xs break-all">{created}</code>
              <Button size="icon-sm" variant="outline" aria-label="Copy" onClick={() => navigator.clipboard.writeText(created).then(() => toast.success('Copied'))}>
                <CopyIcon />
              </Button>
            </div>
          </div>
        )}
        <Table>
          <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Created</TableHead><TableHead>Last used</TableHead><TableHead className="w-12" /></TableRow></TableHeader>
          <TableBody>
            {tokens.data?.map((t) => (
              <TableRow key={t.name}>
                <TableCell className="font-mono">{t.name}</TableCell>
                <TableCell className="text-xs">{t.created}</TableCell>
                <TableCell className="text-xs">{t.last_used || 'never'}</TableCell>
                <TableCell>
                  {canEdit && (
                    <ConfirmButton size="icon-sm" destructive aria-label="Revoke" title={`Revoke token ${t.name}?`} confirmLabel="Revoke" onConfirm={() => revoke.mutate(t.name)}>
                      <Trash2Icon />
                    </ConfirmButton>
                  )}
                </TableCell>
              </TableRow>
            ))}
            {tokens.data?.length === 0 && <TableRow><TableCell colSpan={4} className="text-center text-muted-foreground">No tokens</TableCell></TableRow>}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}

function Security() {
  const me = useSession()
  return (
    <Card>
      <CardHeader>
        <CardTitle>Access &amp; security</CardTitle>
      </CardHeader>
      <CardContent className="grid gap-2 text-sm">
        <div>Signed in as <b>{me.user}</b> <Badge variant={me.role === 'admin' ? 'default' : 'secondary'}>{me.role}</Badge></div>
        <div>
          HTTPS: {me.tls ? <Badge>enabled</Badge> : <Badge variant="outline">off</Badge>}{' '}
          <span className="text-muted-foreground">
            {me.tls ? 'Served directly over TLS.' : 'Use an SSH tunnel or a TLS reverse proxy, or enable built-in TLS (RICHRULE_TLS_CERT / RICHRULE_TLS_KEY, or install.sh --tls).'}
          </span>
        </div>
        <p className="text-muted-foreground">
          Roles come from Linux groups: members of the admin group (default <code>wheel</code>) can change everything;
          members of the viewer group (default <code>firewall-viewers</code>, create it with <code>groupadd firewall-viewers</code>)
          get read-only access. Configure with RICHRULE_ALLOWED_GROUP and RICHRULE_VIEWER_GROUP.
        </p>
      </CardContent>
    </Card>
  )
}

export default function SettingsPage() {
  return (
    <div className="grid gap-6">
      <h1 className="text-2xl font-semibold">Settings</h1>
      <Security />
      <Notifications />
      <AgentTokens />
    </div>
  )
}
