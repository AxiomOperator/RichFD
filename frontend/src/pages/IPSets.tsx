import { ListPlusIcon, PlusIcon, RefreshCwIcon, RssIcon, Trash2Icon } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import type { Feed } from '@/api/types'
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
import { Textarea } from '@/components/ui/textarea'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { ExportMenu } from './Zone'
import { useApplyMode } from '@/lib/apply-mode'
import { useCanEdit } from '@/lib/session'
import { mergeItems, removalTarget } from '@/lib/zone-ops'

const TYPES = ['hash:ip', 'hash:net', 'hash:mac', 'hash:ip,port', 'hash:net,port', 'hash:net,iface', 'hash:ip,mark']

function BulkImport({ name, runtimeAvailable, onClose }: { name: string; runtimeAvailable: boolean; onClose: () => void }) {
  const { target } = useApplyMode()
  const [text, setText] = useState('')
  const imp = useFwMutation(
    () =>
      api.post<{ added: Record<string, number>; invalid: string[]; parsed: number }>(`/ipsets/${encodeURIComponent(name)}/import`, {
        text,
        target: runtimeAvailable ? target : 'permanent',
      }),
    (_v, r) =>
      `Parsed ${r.parsed}; added ${Object.entries(r.added).map(([k, n]) => `${n} (${k})`).join(', ')}` +
      (r.invalid.length ? `; skipped invalid: ${r.invalid.slice(0, 3).join(', ')}` : ''),
  )
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Bulk add to {name}</DialogTitle>
          <DialogDescription>
            Paste addresses or networks, or load a .txt / .csv file: addresses are picked from any column; headers and # comments are ignored.
            Existing entries are skipped. Or load a text file.
          </DialogDescription>
        </DialogHeader>
        <Textarea rows={10} className="font-mono text-xs" value={text} onChange={(e) => setText(e.target.value)} placeholder={'203.0.113.0/24\n198.51.100.7'} />
        <input type="file" accept=".txt,.list,.zone,.csv,text/plain" className="text-sm"
          onChange={(e) => e.target.files?.[0]?.text().then(setText)} />
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => imp.mutateAsync(undefined).then(onClose, () => {})} disabled={!text.trim() || imp.isPending}>Import</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function FeedRow({ name, feed }: { name: string; feed?: Feed }) {
  const canEdit = useCanEdit()
  const [url, setUrl] = useState('')
  const set = useFwMutation(() => api.put<Feed>(`/feeds/${encodeURIComponent(name)}`, { url, interval_hours: 24 }), (_v, f) =>
    f.last_error ? `Feed saved, download failed: ${f.last_error}` : `Feed saved: ${f.count} entries loaded`)
  const refresh = useFwMutation(() => api.post<Feed>(`/feeds/${encodeURIComponent(name)}/refresh`), (_v, f) =>
    f.last_error ? `Refresh failed: ${f.last_error}` : `Refreshed: ${f.count} entries`)
  const remove = useFwMutation(() => api.delete(`/feeds/${encodeURIComponent(name)}`), 'Feed removed (entries kept)')
  if (feed)
    return (
      <div className="flex flex-wrap items-center gap-2 rounded-md border border-sky-500/30 bg-sky-500/5 px-3 py-2 text-xs">
        <RssIcon className="size-3.5 text-sky-600" />
        <span className="min-w-0 flex-1 truncate">
          Auto-updated every {feed.interval_hours}h from <span className="font-mono">{feed.url}</span>
          {feed.last_ok ? ` · last ${new Date(feed.last_ok * 1000).toLocaleString()} (${feed.count} entries)` : ''}
          {feed.last_error && <span className="text-destructive"> · {feed.last_error}</span>}
        </span>
        {canEdit && <Button size="icon-xs" variant="ghost" aria-label="Refresh now" onClick={() => refresh.mutate(undefined)}><RefreshCwIcon /></Button>}
        {canEdit && <Button size="icon-xs" variant="ghost" aria-label="Remove feed" onClick={() => remove.mutate(undefined)}><Trash2Icon /></Button>}
      </div>
    )
  if (!canEdit) return null
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-muted-foreground">Keep this set updated from a URL (feed)…</summary>
      <form className="mt-2 flex gap-2" onSubmit={(e) => { e.preventDefault(); set.mutate(undefined) }}>
        <Input className="h-8" placeholder="https://… (one address per line)" value={url} onChange={(e) => setUrl(e.target.value)} />
        <Button size="sm" type="submit" disabled={!url.startsWith('http')}>Save &amp; load</Button>
      </form>
    </details>
  )
}

function IPSetCard({ name, runtime, permanent, feed }: { name: string; runtime?: IPSet; permanent?: IPSet; feed?: Feed }) {
  const { target } = useApplyMode()
  const [entry, setEntry] = useState('')
  const [bulk, setBulk] = useState(false)
  const canEdit = useCanEdit()
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
          <CardAction className="flex gap-1">
            {canEdit && <Button size="sm" variant="outline" onClick={() => setBulk(true)}><ListPlusIcon /> Bulk add</Button>}
            <ExportMenu kind="ipset" name={name} />
            <ConfirmButton size="icon-sm" destructive aria-label="Delete ipset" title={`Delete IP set ${name}?`}
              description="Fails if any zone or rule still references it." confirmLabel="Delete" onConfirm={() => del.mutate(undefined)}>
              <Trash2Icon />
            </ConfirmButton>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="grid gap-3">
        {permanent && <FeedRow name={name} feed={feed} />}
        {canEdit && <form className="flex gap-2" onSubmit={(e) => {
          e.preventDefault()
          change.mutateAsync({ action: 'add', entry, target: runtime ? target : 'permanent' }).then(() => setEntry(''), () => {})
        }}>
          <Input className="h-8" placeholder="entry (e.g. 203.0.113.7)" value={entry} onChange={(e) => setEntry(e.target.value)} />
          <Button size="sm" type="submit" disabled={!entry}><PlusIcon /> Add</Button>
        </form>}
        <ul className="max-h-72 divide-y overflow-y-auto rounded-md border">
          {entries.map((m) => (
            <li key={m.key} className="flex items-center gap-2 px-3 py-1.5 font-mono text-sm">
              <span className="flex-1">{m.item}</span>
              <PresenceBadge where={m} />
              <Button variant="ghost" size="icon-xs" aria-label="Remove entry" disabled={!canEdit} onClick={() => {
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
      {bulk && <BulkImport name={name} runtimeAvailable={!!runtime} onClose={() => setBulk(false)} />}
    </Card>
  )
}

export default function IPSetsPage() {
  const ipsets = useIPSets()
  const canEdit = useCanEdit()
  const feeds = useQuery({ queryKey: ['feeds'], queryFn: () => api.get<Record<string, Feed>>('/feeds') })
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
        <CardContent hidden={!canEdit}>
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
        {names.map((n) => <IPSetCard key={n} name={n} runtime={rt.get(n)} permanent={pm.get(n)} feed={feeds.data?.[n]} />)}
      </div>
    </div>
  )
}
