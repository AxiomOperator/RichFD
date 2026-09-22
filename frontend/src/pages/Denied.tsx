import { useQuery } from '@tanstack/react-query'
import { PauseIcon, PlayIcon, SearchIcon, ShieldCheckIcon } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { api, apiUrl } from '@/api/client'
import { useFwMutation, useStatus } from '@/api/hooks'
import type { DeniedEntry, RichRule } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useCanEdit } from '@/lib/session'

const MAX = 2000

/** A rich rule that would allow traffic like this entry. */
function allowRule(e: DeniedEntry): RichRule {
  const v6 = e.src.includes(':')
  const ports = ['tcp', 'udp', 'sctp', 'dccp'].includes(e.proto)
  return {
    family: v6 ? 'ipv6' : 'ipv4',
    priority: 0,
    source: { addr: e.src, mac: '', ipset: '', invert: false },
    destination: null,
    element: ports && e.dpt ? { type: 'port', port: String(e.dpt), protocol: e.proto } : e.proto ? { type: 'protocol', value: e.proto } : null,
    log: null,
    audit: null,
    action: { type: 'accept', reject_type: '', set: '', limit: null },
  }
}

export default function DeniedPage() {
  const status = useStatus()
  const canEdit = useCanEdit()
  const navigate = useNavigate()
  const recent = useQuery({ queryKey: ['denied'], queryFn: () => api.get<DeniedEntry[]>('/denied?limit=500') })
  const [live, setLive] = useState<DeniedEntry[]>([])
  const [paused, setPaused] = useState(false)
  const [connected, setConnected] = useState(false)
  const pausedRef = useRef(paused)
  useEffect(() => {
    pausedRef.current = paused
  }, [paused])
  const [q, setQ] = useState('')
  const [kind, setKind] = useState('denied')
  const setLogDenied = useFwMutation((value: string) => api.post('/log-denied', { value }), 'Log-denied updated')

  useEffect(() => {
    const es = new EventSource(apiUrl('/denied/stream'))
    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.onmessage = (ev) => {
      if (pausedRef.current) return
      try {
        const e = JSON.parse(ev.data) as DeniedEntry
        setLive((l) => [e, ...l].slice(0, MAX))
      } catch {
        /* ignore */
      }
    }
    return () => es.close()
  }, [])

  const all = useMemo(() => {
    const seen = new Set<string>()
    return [...live, ...(recent.data ?? [])].filter((e) => {
      const k = e.cursor || `${e.ts}${e.src}${e.dpt}`
      if (seen.has(k)) return false
      seen.add(k)
      return true
    })
  }, [live, recent.data])

  const needle = q.trim().toLowerCase()
  const rows = all.filter(
    (e) =>
      (kind === 'all' || e.kind === kind) &&
      (!needle ||
        [e.src, e.dst, e.proto, e.zone, e.in, e.prefix, e.dpt?.toString() ?? ''].some((v) => v.toLowerCase().includes(needle))),
  )

  const top = useMemo(() => {
    const counts = new Map<string, number>()
    for (const e of rows) counts.set(e.src, (counts.get(e.src) ?? 0) + 1)
    return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5)
  }, [rows])

  const logDenied = status.data?.log_denied ?? 'off'
  const zoneFor = (e: DeniedEntry) =>
    e.zone || Object.entries(status.data?.active_zones ?? {}).find(([, z]) => z.interfaces.includes(e.in))?.[0] || status.data?.default_zone || ''

  return (
    <div className="grid gap-6">
      {logDenied === 'off' && (
        <Card className="border-amber-500/40">
          <CardHeader>
            <CardTitle>Denied-packet logging is off</CardTitle>
            <CardDescription>firewalld only logs rejected/dropped packets when log-denied is enabled. Entries from rich rules with "log" still appear.</CardDescription>
            {canEdit && (
              <CardAction>
                <Button size="sm" onClick={() => setLogDenied.mutate('unicast')}>Enable (unicast)</Button>
              </CardAction>
            )}
          </CardHeader>
        </Card>
      )}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            Packet log
            <span className={`size-2 rounded-full ${connected && !paused ? 'animate-pulse bg-emerald-500' : 'bg-muted-foreground/40'}`} />
            <span className="text-xs font-normal text-muted-foreground">{paused ? 'paused' : connected ? 'live' : 'connecting…'}</span>
          </CardTitle>
          <CardDescription>
            Kernel log entries from firewalld (log-denied: <b>{logDenied}</b>) and rich rules with logging.
            {top.length > 0 && <> Top sources: {top.map(([s, n]) => `${s} (${n})`).join(', ')}.</>}
          </CardDescription>
          <CardAction className="flex gap-2">
            <Input placeholder="Filter address, port, zone…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56" />
            <Select value={kind} onValueChange={setKind}>
              <SelectTrigger size="sm" className="w-32" aria-label="Kind"><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="denied">Denied</SelectItem>
                <SelectItem value="logged">Rule logs</SelectItem>
                <SelectItem value="invalid">Invalid</SelectItem>
                <SelectItem value="all">All</SelectItem>
              </SelectContent>
            </Select>
            <Button size="sm" variant="outline" onClick={() => setPaused((p) => !p)}>
              {paused ? <PlayIcon /> : <PauseIcon />} {paused ? 'Resume' : 'Pause'}
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-40">Time</TableHead>
                <TableHead>Zone / prefix</TableHead>
                <TableHead>In</TableHead>
                <TableHead>Source</TableHead>
                <TableHead>Destination</TableHead>
                <TableHead>Proto</TableHead>
                <TableHead className="w-20" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {rows.slice(0, 500).map((e, i) => (
                <TableRow key={e.cursor || i}>
                  <TableCell className="font-mono text-xs whitespace-nowrap">{e.ts.replace('T', ' ').slice(0, 19)}</TableCell>
                  <TableCell className="text-xs">
                    {e.zone ? <span className="font-mono">{e.zone}</span> : e.policy ? <span className="font-mono">policy {e.policy}</span> : <span className="text-muted-foreground">{e.prefix || '—'}</span>}{' '}
                    {e.action && <Badge variant={e.kind === 'denied' ? 'destructive' : 'secondary'}>{e.action}</Badge>}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{e.in}</TableCell>
                  <TableCell className="font-mono text-xs">{e.src}{e.spt ? `:${e.spt}` : ''}</TableCell>
                  <TableCell className="font-mono text-xs">{e.dst}{e.dpt ? `:${e.dpt}` : ''}</TableCell>
                  <TableCell className="text-xs">{e.proto}{e.icmp_type ? ` type ${e.icmp_type}` : ''}</TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <Button variant="ghost" size="icon-sm" aria-label="Explain"
                          onClick={() => navigate(`/tester?src=${encodeURIComponent(e.src)}&proto=${e.proto}&dport=${e.dpt ?? ''}&iface=${encodeURIComponent(e.in)}`)}>
                          <SearchIcon />
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent>Explain in the traffic tester</TooltipContent>
                    </Tooltip>
                    {canEdit && e.kind !== 'logged' && zoneFor(e) && (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <Button variant="ghost" size="icon-sm" aria-label="Create allow rule"
                            onClick={() => navigate(`/zones/${encodeURIComponent(zoneFor(e))}`, { state: { draft: { rule: '', parsed: allowRule(e) } } })}>
                            <ShieldCheckIcon />
                          </Button>
                        </TooltipTrigger>
                        <TooltipContent>Create an allow rule in zone {zoneFor(e)}</TooltipContent>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {rows.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="py-8 text-center text-muted-foreground">
                    {recent.isPending ? 'Loading…' : 'No matching packet-log entries yet.'}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  )
}
