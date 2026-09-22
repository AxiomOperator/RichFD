import { useQuery } from '@tanstack/react-query'
import { PauseIcon, PlayIcon, SearchIcon, ShieldCheckIcon } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router'
import { api, apiUrl } from '@/api/client'
import { useFwMutation, useStatus } from '@/api/hooks'
import type { DeniedEntry, DeniedStats, RichRule } from '@/api/types'
import { BlockIpButton } from '@/components/BlockIp'
import { BarList, ColumnChart, StatTile } from '@/components/charts'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
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

function LiveFeed() {
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
                <TableHead className="w-28" />
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
                    {e.kind !== 'logged' && <BlockIpButton ip={e.src} zone={zoneFor(e)} />}
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

const RANGES = [
  { hours: 1, label: 'Last hour' },
  { hours: 6, label: '6 hours' },
  { hours: 24, label: '24 hours' },
  { hours: 168, label: '7 days' },
]

function Dashboard() {
  const navigate = useNavigate()
  const status = useStatus()
  const [hours, setHours] = useState(24)
  const [port, setPort] = useState('22')
  const portNum = /^\d+$/.test(port) ? Number(port) : null
  const stats = useQuery({
    queryKey: ['denied-stats', hours, portNum],
    queryFn: () => api.get<DeniedStats>(`/denied/stats?hours=${hours}${portNum !== null ? `&port=${portNum}` : ''}`),
    refetchInterval: 30_000,
    placeholderData: (prev) => prev,
  })
  const d = stats.data
  const explain = (src: string, dport?: string) => (
    <Button variant="ghost" size="icon-sm" aria-label={`Explain ${src}`}
      onClick={() => navigate(`/tester?src=${encodeURIComponent(src)}${dport ? `&dport=${dport}` : ''}`)}>
      <SearchIcon />
    </Button>
  )
  return (
    <div className="grid gap-4">
      {/* Filters: one row, above everything they scope. */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex rounded-md border p-0.5">
          {RANGES.map((r) => (
            <Button key={r.hours} size="sm" variant={hours === r.hours ? 'secondary' : 'ghost'} onClick={() => setHours(r.hours)}>
              {r.label}
            </Button>
          ))}
        </div>
        <label className="flex items-center gap-2 text-sm">
          Focus port
          <Input className="h-8 w-20" value={port} onChange={(e) => setPort(e.target.value)} inputMode="numeric" placeholder="22" />
        </label>
        {status.data?.log_denied === 'off' && <span className="text-sm text-amber-700 dark:text-amber-400">log-denied is off: only rich-rule logs are counted</span>}
      </div>
      {!d ? (
        stats.isError ? <p className="text-destructive">{stats.error.message}</p> : <Skeleton className="h-80" />
      ) : (
        <div className={`grid gap-4 ${stats.isFetching ? 'opacity-70' : ''}`}>
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Blocked packets" value={d.total.toLocaleString()} hint={RANGES.find((r) => r.hours === hours)?.label} />
            <StatTile label="Distinct sources" value={d.unique_sources.toLocaleString()} />
            <StatTile label="Most targeted port" value={d.top_ports[0]?.port ?? '—'} hint={d.top_ports[0] ? `${d.top_ports[0].count} packets` : undefined} />
            <StatTile label="Top source" value={<span className="font-mono text-lg">{d.top_sources[0]?.src ?? '—'}</span>}
              hint={d.top_sources[0] ? `${d.top_sources[0].count} packets` : undefined} />
          </div>
          <Card>
            <CardHeader>
              <CardTitle>Blocked packets over time</CardTitle>
              <CardDescription>Per {d.bucket_minutes} minutes.</CardDescription>
            </CardHeader>
            <CardContent>
              <ColumnChart data={d.timeline} label="Blocked packets over time" />
            </CardContent>
          </Card>
          <div className="grid gap-4 xl:grid-cols-2">
            <Card>
              <CardHeader>
                <CardTitle>Top 10 sources</CardTitle>
                <CardDescription>Addresses with the most blocked packets, and the ports they tried.</CardDescription>
              </CardHeader>
              <CardContent>
                <BarList
                  empty="No blocked traffic in this period"
                  items={d.top_sources.map((s) => ({
                    key: s.src, label: s.src, value: s.count, detail: s.ports.join(', '),
                    actions: <>{explain(s.src)}<BlockIpButton ip={s.src} /></>,
                  }))}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle>{portNum !== null ? `Top 10 addresses hitting port ${portNum}` : 'Pick a port to focus on'}</CardTitle>
                <CardDescription>{portNum === 22 ? 'SSH brute-force candidates — consider Fail2ban or the rate-limit template.' : 'Sources blocked on the focus port.'}</CardDescription>
              </CardHeader>
              <CardContent>
                <BarList
                  empty={portNum !== null ? `Nothing blocked on port ${portNum}` : 'Enter a port above'}
                  items={(d.top_sources_on_port ?? []).map((s) => ({
                    key: s.src, label: s.src, value: s.count,
                    actions: <>{explain(s.src, String(portNum))}<BlockIpButton ip={s.src} /></>,
                  }))}
                />
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>Top targeted ports</CardTitle></CardHeader>
              <CardContent>
                <BarList empty="No data" items={d.top_ports.map((p) => ({ key: p.port, label: p.port, value: p.count }))} />
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle>By zone and interface</CardTitle></CardHeader>
              <CardContent className="grid gap-4">
                <BarList empty="No data" items={d.top_zones.map((z) => ({ key: z.zone, label: z.zone, value: z.count }))} />
                <BarList empty="No data" items={d.top_interfaces.map((z) => ({ key: z.interface, label: z.interface, value: z.count }))} />
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}

export default function DeniedPage() {
  return (
    <Tabs defaultValue="dashboard" className="grid gap-4">
      <div className="flex items-center gap-3">
        <h1 className="text-2xl font-semibold">Denied traffic</h1>
        <TabsList>
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="live">Live feed</TabsTrigger>
        </TabsList>
      </div>
      <TabsContent value="dashboard"><Dashboard /></TabsContent>
      <TabsContent value="live"><LiveFeed /></TabsContent>
    </Tabs>
  )
}
