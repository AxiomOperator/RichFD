import { PlusIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { api } from '@/api/client'
import { useFwMutation, useIPSets } from '@/api/hooks'
import type { IPSet } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { PresenceBadge } from '@/components/PresenceBadge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { useApplyMode } from '@/lib/apply-mode'
import { mergeItems, removalTarget } from '@/lib/zone-ops'

const TYPES = ['hash:ip', 'hash:net', 'hash:mac', 'hash:ip,port', 'hash:net,port', 'hash:net,iface', 'hash:ip,mark']

function IPSetCard({ name, runtime, permanent }: { name: string; runtime?: IPSet; permanent?: IPSet }) {
  const { target } = useApplyMode()
  const [entry, setEntry] = useState('')
  const set = permanent ?? runtime!
  const entries = mergeItems(runtime?.entries, permanent?.entries, (e) => e)
  const change = useFwMutation(
    (v: { action: 'add' | 'remove'; entry: string; target: string }) =>
      api.post(`/ipsets/${encodeURIComponent(name)}/entries`, v),
  )
  const del = useFwMutation(() => api.delete(`/ipsets/${encodeURIComponent(name)}`), `IP set ${name} deleted — reload to apply`)

  return (
    <Card>
      <CardHeader>
        <CardTitle className="font-mono">{name}</CardTitle>
        <CardDescription className="flex flex-wrap gap-1">
          <Badge variant="secondary">{set.type}</Badge>
          {Object.entries(set.options).map(([k, v]) => (
            <Badge key={k} variant="outline">{k}={v}</Badge>
          ))}
          {!runtime && <Badge variant="outline">permanent only — reload to activate</Badge>}
          <span className="ml-1">{entries.length} entries · use as <code>ipset:{name}</code> in sources</span>
        </CardDescription>
        {permanent && (
          <CardAction>
            <ConfirmButton size="icon-sm" destructive aria-label="Delete ipset" title={`Delete IP set ${name}?`}
              description="Fails if any zone or rule still references it." confirmLabel="Delete" onConfirm={() => del.mutate(undefined)}>
              <Trash2Icon />
            </ConfirmButton>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="grid gap-3">
        <form className="flex gap-2" onSubmit={(e) => {
          e.preventDefault()
          change.mutateAsync({ action: 'add', entry, target: runtime ? target : 'permanent' }).then(() => setEntry(''), () => {})
        }}>
          <Input className="h-8" placeholder="entry (e.g. 203.0.113.7)" value={entry} onChange={(e) => setEntry(e.target.value)} />
          <Button size="sm" type="submit" disabled={!entry}><PlusIcon /> Add</Button>
        </form>
        <ul className="max-h-72 divide-y overflow-y-auto rounded-md border">
          {entries.map((m) => (
            <li key={m.key} className="flex items-center gap-2 px-3 py-1.5 font-mono text-sm">
              <span className="flex-1">{m.item}</span>
              <PresenceBadge where={m} />
              <Button variant="ghost" size="icon-xs" aria-label="Remove entry" onClick={() => {
                const t = removalTarget(m, target)
                if (t) change.mutate({ action: 'remove', entry: m.item, target: t })
              }}>
                <Trash2Icon />
              </Button>
            </li>
          ))}
          {entries.length === 0 && <li className="px-3 py-2 text-sm text-muted-foreground">Empty</li>}
        </ul>
      </CardContent>
    </Card>
  )
}

export default function IPSetsPage() {
  const ipsets = useIPSets()
  const [form, setForm] = useState({ name: '', type: 'hash:ip', family: 'inet' })
  const create = useFwMutation(() => api.post('/ipsets', form), 'IP set created — reload to activate it')

  if (ipsets.isPending) return <Skeleton className="h-96 w-full" />
  if (ipsets.isError) return <p className="text-destructive">{ipsets.error.message}</p>
  const rt = new Map(ipsets.data.runtime.map((s) => [s.name, s]))
  const pm = new Map(ipsets.data.permanent.map((s) => [s.name, s]))
  const names = [...new Set([...rt.keys(), ...pm.keys()])].sort()

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle>IP sets</CardTitle>
          <CardDescription>Named address lists usable as rich rule sources/destinations and zone sources.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="flex flex-wrap items-center gap-2" onSubmit={(e) => {
            e.preventDefault()
            create.mutateAsync(undefined).then(() => setForm({ ...form, name: '' }), () => {})
          }}>
            <Input className="h-8 w-48" placeholder="name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            <Select value={form.type} onValueChange={(type) => setForm({ ...form, type })}>
              <SelectTrigger size="sm" className="w-40" aria-label="Type"><SelectValue /></SelectTrigger>
              <SelectContent>{TYPES.map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}</SelectContent>
            </Select>
            <Select value={form.family} onValueChange={(family) => setForm({ ...form, family })}>
              <SelectTrigger size="sm" className="w-28" aria-label="Family"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="inet">IPv4</SelectItem>
                <SelectItem value="inet6">IPv6</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" type="submit" disabled={create.isPending}><PlusIcon /> Create IP set</Button>
          </form>
        </CardContent>
      </Card>
      {names.length === 0 && <p className="text-sm text-muted-foreground">No IP sets defined.</p>}
      <div className="grid gap-4 lg:grid-cols-2">
        {names.map((n) => <IPSetCard key={n} name={n} runtime={rt.get(n)} permanent={pm.get(n)} />)}
      </div>
    </div>
  )
}
