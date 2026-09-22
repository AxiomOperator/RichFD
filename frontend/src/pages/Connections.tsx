import { useQuery } from '@tanstack/react-query'
import { PauseIcon, PlayIcon, RefreshCwIcon, SearchIcon } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router'
import { api } from '@/api/client'
import type { ConnectionsData, SocketRow } from '@/api/types'
import { BlockIpButton } from '@/components/BlockIp'
import { StatTile } from '@/components/charts'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'

const classStyle: Record<string, string> = {
  public: 'border-amber-500/50 text-amber-700 dark:text-amber-400',
  private: '',
  loopback: 'text-muted-foreground',
}

export default function ConnectionsPage() {
  const [paused, setPaused] = useState(false)
  const [q, setQ] = useState('')
  const [dir, setDir] = useState('in')
  const [cls, setCls] = useState('remote')
  const navigate = useNavigate()
  const conns = useQuery({
    queryKey: ['connections'],
    queryFn: () => api.get<ConnectionsData>('/connections'),
    refetchInterval: paused ? false : 3000,
  })
  const data = conns.data
  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (data?.sockets ?? []).filter(
      (r) =>
        (dir === 'all' || r.direction === dir) &&
        (cls === 'all' || (cls === 'remote' ? !['loopback', 'any'].includes(r.peer_class) : r.peer_class === cls)) &&
        (!needle || [r.peer_addr, r.local_port, r.peer_port, r.process, r.state].some((v) => v.toLowerCase().includes(needle))),
    )
  }, [data, q, dir, cls])

  if (conns.isPending) return <Skeleton className="h-96 w-full" />
  if (conns.isError) return <p className="text-destructive">{conns.error.message}</p>

  const established = data!.sockets.filter((r) => r.state === 'ESTAB')
  const inbound = established.filter((r) => r.direction === 'in')
  const publicPeers = new Set(established.filter((r) => r.peer_class === 'public').map((r) => r.peer_addr))
  const listening = data!.sockets.filter((r) => r.listening)
  const blockable = (r: SocketRow) => ['public', 'private'].includes(r.peer_class) && r.peer_addr && !r.listening

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-center gap-2">
        <h1 className="mr-auto text-2xl font-semibold">Connections</h1>
        <Button size="sm" variant="outline" onClick={() => setPaused((p) => !p)}>
          {paused ? <PlayIcon /> : <PauseIcon />} {paused ? 'Resume' : 'Pause'} auto-refresh
        </Button>
        <Button size="sm" variant="outline" onClick={() => conns.refetch()}><RefreshCwIcon /> Refresh</Button>
      </div>
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Established" value={established.length} />
        <StatTile label="Inbound (to local services)" value={inbound.length} />
        <StatTile label="Distinct public peers" value={publicPeers.size} />
        <StatTile label="Listening sockets" value={listening.length} />
      </div>
      <Tabs defaultValue="sockets">
        <TabsList>
          <TabsTrigger value="sockets">Sockets (ss)</TabsTrigger>
          <TabsTrigger value="conntrack">Tracked flows (conntrack)</TabsTrigger>
          <TabsTrigger value="listening">Listening services</TabsTrigger>
        </TabsList>
        <TabsContent value="sockets" className="mt-4">
          <Card className={conns.isFetching ? 'opacity-95' : ''}>
            <CardHeader>
              <CardTitle>Active sockets</CardTitle>
              <CardDescription>
                Refreshes every 3 seconds. Blocking adds a high-priority drop rule and can close the existing connection.
                {!data!.processes_visible && ' Process names need RichFD to run as root.'}
              </CardDescription>
              <CardAction className="flex gap-2">
                <Input placeholder="Filter address, port, process…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56" />
                <Select value={dir} onValueChange={setDir}>
                  <SelectTrigger size="sm" className="w-32" aria-label="Direction"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="in">Inbound</SelectItem>
                    <SelectItem value="out">Outbound</SelectItem>
                    <SelectItem value="all">All</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={cls} onValueChange={setCls}>
                  <SelectTrigger size="sm" className="w-32" aria-label="Peer type"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="remote">Non-loopback</SelectItem>
                    <SelectItem value="all">Any peer</SelectItem>
                    <SelectItem value="public">Public</SelectItem>
                    <SelectItem value="private">Private</SelectItem>
                    <SelectItem value="loopback">Loopback</SelectItem>
                  </SelectContent>
                </Select>
              </CardAction>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Proto</TableHead>
                    <TableHead>State</TableHead>
                    <TableHead>Local</TableHead>
                    <TableHead>Peer</TableHead>
                    <TableHead>Process</TableHead>
                    <TableHead className="w-20" />
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {rows.slice(0, 400).map((r, i) => (
                    <TableRow key={`${r.proto}${r.local_addr}${r.local_port}${r.peer_addr}${r.peer_port}${i}`}>
                      <TableCell className="text-xs">{r.proto}</TableCell>
                      <TableCell className="text-xs">
                        {r.state} {r.direction === 'in' && <Badge variant="secondary">in</Badge>}
                      </TableCell>
                      <TableCell className="font-mono text-xs">{r.local_addr}:{r.local_port}</TableCell>
                      <TableCell className="font-mono text-xs">
                        {r.peer_addr}{r.peer_port !== '*' ? `:${r.peer_port}` : ''}{' '}
                        {r.peer_class !== 'any' && <Badge variant="outline" className={classStyle[r.peer_class] ?? ''}>{r.peer_class}</Badge>}
                      </TableCell>
                      <TableCell className="text-xs">{r.process ? `${r.process} (${r.pid})` : '—'}</TableCell>
                      <TableCell className="text-right whitespace-nowrap">
                        {r.direction === 'in' && blockable(r) && (
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <Button variant="ghost" size="icon-sm" aria-label="Explain"
                                onClick={() => navigate(`/tester?src=${encodeURIComponent(r.peer_addr)}&proto=${r.proto}&dport=${r.local_port}`)}>
                                <SearchIcon />
                              </Button>
                            </TooltipTrigger>
                            <TooltipContent>Why is this allowed?</TooltipContent>
                          </Tooltip>
                        )}
                        {blockable(r) && <BlockIpButton ip={r.peer_addr} allowTerminate />}
                      </TableCell>
                    </TableRow>
                  ))}
                  {rows.length === 0 && (
                    <TableRow><TableCell colSpan={6} className="py-6 text-center text-muted-foreground">No matching connections</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="conntrack" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Connection tracking table</CardTitle>
              <CardDescription>
                Every flow the kernel is tracking, including forwarded and NATed traffic (containers, VMs).
                {data!.conntrack_error && <span className="block text-amber-700 dark:text-amber-400">{data!.conntrack_error}</span>}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow><TableHead>Proto</TableHead><TableHead>State</TableHead><TableHead>Source</TableHead><TableHead>Destination</TableHead><TableHead>Flags</TableHead><TableHead className="w-12" /></TableRow>
                </TableHeader>
                <TableBody>
                  {data!.conntrack.slice(0, 400).map((c, i) => (
                    <TableRow key={i}>
                      <TableCell className="text-xs">{c.proto}</TableCell>
                      <TableCell className="text-xs">{c.state || '—'}</TableCell>
                      <TableCell className="font-mono text-xs">{c.src}{c.sport ? `:${c.sport}` : ''}</TableCell>
                      <TableCell className="font-mono text-xs">{c.dst}{c.dport ? `:${c.dport}` : ''}</TableCell>
                      <TableCell className="space-x-1">
                        {c.nat && <Badge variant="secondary">NAT</Badge>}
                        {c.assured && <Badge variant="outline">assured</Badge>}
                      </TableCell>
                      <TableCell>{['public', 'private'].includes(c.src_class) && <BlockIpButton ip={c.src} allowTerminate />}</TableCell>
                    </TableRow>
                  ))}
                  {data!.conntrack.length === 0 && (
                    <TableRow><TableCell colSpan={6} className="py-6 text-center text-muted-foreground">No conntrack data</TableCell></TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="listening" className="mt-4">
          <Card>
            <CardHeader>
              <CardTitle>Listening services</CardTitle>
              <CardDescription>What this host accepts connections on. Use the traffic tester to check whether the firewall exposes each one.</CardDescription>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader><TableRow><TableHead>Proto</TableHead><TableHead>Address</TableHead><TableHead>Port</TableHead><TableHead>Process</TableHead><TableHead className="w-12" /></TableRow></TableHeader>
                <TableBody>
                  {listening
                    .slice()
                    .sort((a, b) => Number(a.local_port) - Number(b.local_port))
                    .map((r, i) => (
                      <TableRow key={i}>
                        <TableCell className="text-xs">{r.proto}</TableCell>
                        <TableCell className="font-mono text-xs">
                          {r.local_addr} {['127.0.0.1', '::1', '127.0.0.53', '127.0.0.54'].includes(r.local_addr) && <Badge variant="outline">local only</Badge>}
                        </TableCell>
                        <TableCell className="font-mono text-xs">{r.local_port}</TableCell>
                        <TableCell className="text-xs">{r.process || '—'}</TableCell>
                        <TableCell>
                          <Button variant="ghost" size="icon-sm" aria-label="Test exposure"
                            onClick={() => navigate(`/tester?src=203.0.113.1&proto=${r.proto}&dport=${r.local_port}`)}>
                            <SearchIcon />
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
