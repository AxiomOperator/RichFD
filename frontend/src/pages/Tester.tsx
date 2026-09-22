import { CheckCircle2Icon, CircleDashedIcon, CircleHelpIcon, MinusCircleIcon, SearchIcon } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useSearchParams } from 'react-router'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { useZones } from '@/api/hooks'
import type { TesterResult } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'

const PROTOS = ['tcp', 'udp', 'icmp', 'ipv6-icmp', 'sctp', 'gre', 'esp']
const ANY = '__any__'

const verdictStyle: Record<string, string> = {
  ACCEPT: 'bg-emerald-600 text-white',
  REJECT: 'bg-destructive text-white',
  DROP: 'bg-destructive text-white',
  FORWARDED: 'bg-sky-600 text-white',
}

export default function TesterPage() {
  const [params] = useSearchParams()
  const zones = useZones()
  const interfaces = [...new Set(zones.data?.flatMap((z) => z.interfaces) ?? [])].sort()
  const [f, setF] = useState({
    src: params.get('src') ?? '',
    protocol: params.get('proto') ?? 'tcp',
    dst_port: params.get('dport') ?? '',
    src_port: '',
    dst: '',
    interface: params.get('iface') ?? '',
    icmp_type: '',
    config: 'runtime',
  })
  const [result, setResult] = useState<TesterResult | null>(null)
  const [showAll, setShowAll] = useState(false)
  const [busy, setBusy] = useState(false)
  const hasPorts = ['tcp', 'udp', 'sctp', 'dccp'].includes(f.protocol)

  async function run(e?: FormEvent) {
    e?.preventDefault()
    setBusy(true)
    try {
      const body = {
        ...f,
        dst_port: hasPorts && f.dst_port ? Number(f.dst_port) : null,
        src_port: hasPorts && f.src_port ? Number(f.src_port) : null,
      }
      setResult(await api.post<TesterResult>('/tester', body))
    } catch (err) {
      toast.error((err as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle>Why is this blocked?</CardTitle>
          <CardDescription>
            Simulates how firewalld handles a new incoming connection to this host: which zone it lands in, and which
            policy, rule, service or target decides. Best-effort model of firewalld's own configuration.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={run} className="grid gap-4">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="grid gap-1.5">
                <Label htmlFor="t-src">Source address</Label>
                <Input id="t-src" required value={f.src} onChange={(e) => setF({ ...f, src: e.target.value })} placeholder="203.0.113.7" />
              </div>
              <div className="grid gap-1.5">
                <Label>Protocol</Label>
                <Select value={f.protocol} onValueChange={(protocol) => setF({ ...f, protocol })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>{PROTOS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}</SelectContent>
                </Select>
              </div>
              {hasPorts ? (
                <div className="grid gap-1.5">
                  <Label htmlFor="t-dport">Destination port</Label>
                  <Input id="t-dport" inputMode="numeric" value={f.dst_port} onChange={(e) => setF({ ...f, dst_port: e.target.value })} placeholder="22" />
                </div>
              ) : f.protocol.includes('icmp') ? (
                <div className="grid gap-1.5">
                  <Label htmlFor="t-icmp">ICMP type (optional)</Label>
                  <Input id="t-icmp" value={f.icmp_type} onChange={(e) => setF({ ...f, icmp_type: e.target.value })} placeholder="echo-request" />
                </div>
              ) : <div />}
              <div className="grid gap-1.5">
                <Label>Arrives on interface</Label>
                <Select value={f.interface || ANY} onValueChange={(v) => setF({ ...f, interface: v === ANY ? '' : v })}>
                  <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value={ANY}>unknown (default zone)</SelectItem>
                    {interfaces.map((i) => <SelectItem key={i} value={i}>{i}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
            </div>
            <details>
              <summary className="cursor-pointer text-sm text-muted-foreground">More options</summary>
              <div className="mt-3 grid gap-3 sm:grid-cols-3">
                {hasPorts && (
                  <div className="grid gap-1.5">
                    <Label htmlFor="t-sport">Source port</Label>
                    <Input id="t-sport" inputMode="numeric" value={f.src_port} onChange={(e) => setF({ ...f, src_port: e.target.value })} />
                  </div>
                )}
                <div className="grid gap-1.5">
                  <Label htmlFor="t-dst">Destination address</Label>
                  <Input id="t-dst" value={f.dst} onChange={(e) => setF({ ...f, dst: e.target.value })} placeholder="for rules with a destination" />
                </div>
                <div className="grid gap-1.5">
                  <Label>Configuration</Label>
                  <Select value={f.config} onValueChange={(config) => setF({ ...f, config })}>
                    <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="runtime">Runtime (active now)</SelectItem>
                      <SelectItem value="permanent">Permanent (after reload)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </details>
            <div>
              <Button type="submit" disabled={busy || !f.src}><SearchIcon /> Test</Button>
            </div>
          </form>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <div className="flex flex-wrap items-center gap-3">
              <span className={`rounded-md px-3 py-1 text-lg font-semibold ${verdictStyle[result.verdict] ?? ''}`}>{result.verdict}</span>
              <div>
                <div className="font-medium">Decided by {result.decided_by}</div>
                <div className="text-sm text-muted-foreground">
                  Zone <span className="font-mono">{result.zone}</span> — {result.zone_reason}
                </div>
              </div>
            </div>
          </CardHeader>
          <CardContent className="grid gap-4">
            {result.notes.length > 0 && (
              <div className="rounded-md border border-amber-500/40 bg-amber-500/10 p-3 text-sm">
                <div className="mb-1 font-medium">Uncertain</div>
                <ul className="list-inside list-disc text-muted-foreground">{result.notes.map((n, i) => <li key={i}>{n}</li>)}</ul>
              </div>
            )}
            {result.steps.some((s) => s.result === 'no-match') && (
              <label className="flex items-center gap-2 text-sm text-muted-foreground">
                <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
                Show {result.steps.filter((s) => s.result === 'no-match').length} non-matching steps
              </label>
            )}
            <ol className="grid gap-1.5">
              {result.steps.filter((s) => showAll || s.result !== 'no-match').map((s, i) => (
                <li key={i} className="flex items-start gap-2 text-sm">
                  {s.verdict ? (
                    <CheckCircle2Icon className={`mt-0.5 size-4 shrink-0 ${s.verdict === 'ACCEPT' ? 'text-emerald-600' : 'text-destructive'}`} />
                  ) : s.result === 'match' ? (
                    <CircleDashedIcon className="mt-0.5 size-4 shrink-0 text-sky-600" />
                  ) : s.result === 'unknown' ? (
                    <CircleHelpIcon className="mt-0.5 size-4 shrink-0 text-amber-500" />
                  ) : (
                    <MinusCircleIcon className="mt-0.5 size-4 shrink-0 text-muted-foreground/50" />
                  )}
                  <div className={s.result === 'no-match' ? 'text-muted-foreground' : ''}>
                    <span className="text-xs text-muted-foreground">{s.stage}</span>
                    <div className="font-mono text-xs break-all">{s.item}</div>
                    {s.detail && <div className="text-xs">{s.detail}</div>}
                  </div>
                  {s.verdict && <Badge className="ml-auto" variant={s.verdict === 'ACCEPT' ? 'default' : 'destructive'}>{s.verdict}</Badge>}
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
