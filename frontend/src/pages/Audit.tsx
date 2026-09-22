import { useState } from 'react'
import { useAudit } from '@/api/hooks'
import { Badge } from '@/components/ui/badge'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

function detailText(d: Record<string, unknown>) {
  const parts: string[] = []
  for (const [k, v] of Object.entries(d)) {
    if (v === '' || v === 0 || v === null || (Array.isArray(v) && v.length === 0)) continue
    parts.push(Array.isArray(v) ? v.join('; ') : k === 'ops' ? String(v) : `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`)
  }
  return parts.join(' · ')
}

export default function AuditPage() {
  const audit = useAudit()
  const [q, setQ] = useState('')
  if (audit.isPending) return <Skeleton className="h-96 w-full" />
  if (audit.isError) return <p className="text-destructive">{audit.error.message}</p>
  const rows = audit.data.filter((e) => JSON.stringify(e).toLowerCase().includes(q.toLowerCase()))
  return (
    <Card>
      <CardHeader>
        <CardTitle>Audit log</CardTitle>
        <CardDescription>Every change made through richrule, newest first.</CardDescription>
        <CardAction>
          <Input placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56" />
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-44">Time</TableHead>
              <TableHead className="w-28">User</TableHead>
              <TableHead className="w-48">Action</TableHead>
              <TableHead>Detail</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((e, i) => (
              <TableRow key={i}>
                <TableCell className="font-mono text-xs whitespace-nowrap">{e.ts.replace('T', ' ')}</TableCell>
                <TableCell>{e.user}</TableCell>
                <TableCell>
                  {e.action} {!e.ok && <Badge variant="destructive">failed</Badge>}
                </TableCell>
                <TableCell className="text-xs break-all whitespace-normal">{detailText(e.detail)}</TableCell>
              </TableRow>
            ))}
            {rows.length === 0 && (
              <TableRow>
                <TableCell colSpan={4} className="text-center text-muted-foreground">No entries</TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
