import { useDirect } from '@/api/hooks'
import type { DirectRules } from '@/api/types'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

function Section({ title, d }: { title: string; d: DirectRules }) {
  const empty = !d.chains.length && !d.rules.length && !d.passthroughs.length
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
        <CardDescription>{empty ? 'No direct configuration.' : `${d.chains.length} chains · ${d.rules.length} rules · ${d.passthroughs.length} passthroughs`}</CardDescription>
      </CardHeader>
      {!empty && (
        <CardContent className="grid gap-4">
          {d.chains.length > 0 && (
            <Table>
              <TableHeader><TableRow><TableHead>Family</TableHead><TableHead>Table</TableHead><TableHead>Chain</TableHead></TableRow></TableHeader>
              <TableBody>
                {d.chains.map((c, i) => <TableRow key={i}><TableCell>{c.ipv}</TableCell><TableCell>{c.table}</TableCell><TableCell className="font-mono">{c.chain}</TableCell></TableRow>)}
              </TableBody>
            </Table>
          )}
          {d.rules.length > 0 && (
            <Table>
              <TableHeader><TableRow><TableHead>Family</TableHead><TableHead>Table</TableHead><TableHead>Chain</TableHead><TableHead>Prio</TableHead><TableHead>Arguments</TableHead></TableRow></TableHeader>
              <TableBody>
                {d.rules.map((r, i) => (
                  <TableRow key={i}>
                    <TableCell>{r.ipv}</TableCell><TableCell>{r.table}</TableCell><TableCell className="font-mono">{r.chain}</TableCell>
                    <TableCell>{r.priority}</TableCell><TableCell className="font-mono text-xs">{r.args.join(' ')}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {d.passthroughs.length > 0 && (
            <Table>
              <TableHeader><TableRow><TableHead>Family</TableHead><TableHead>Passthrough arguments</TableHead></TableRow></TableHeader>
              <TableBody>
                {d.passthroughs.map((p, i) => <TableRow key={i}><TableCell>{p.ipv}</TableCell><TableCell className="font-mono text-xs">{p.args.join(' ')}</TableCell></TableRow>)}
              </TableBody>
            </Table>
          )}
        </CardContent>
      )}
    </Card>
  )
}

export default function DirectPage() {
  const direct = useDirect()
  if (direct.isPending) return <Skeleton className="h-96 w-full" />
  if (direct.isError) return <p className="text-destructive">{direct.error.message}</p>
  return (
    <div className="grid gap-4">
      <div>
        <h1 className="text-2xl font-semibold">Direct rules</h1>
        <p className="max-w-3xl text-sm text-muted-foreground">
          Raw iptables-style rules and passthroughs added with <code>firewall-cmd --direct</code>. This interface is
          deprecated in firewalld and shown read-only; prefer rich rules and policies.
        </p>
      </div>
      <Section title="Runtime" d={direct.data.runtime} />
      <Section title="Permanent" d={direct.data.permanent} />
    </div>
  )
}
