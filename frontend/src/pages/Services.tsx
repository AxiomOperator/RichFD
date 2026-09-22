import { useState } from 'react'
import { useServices } from '@/api/hooks'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'

export default function ServicesPage() {
  const services = useServices()
  const [q, setQ] = useState('')
  if (services.isPending) return <Skeleton className="h-96 w-full" />
  if (services.isError) return <p className="text-destructive">{services.error.message}</p>
  const needle = q.toLowerCase()
  const rows = services.data.filter(
    (s) =>
      s.name.includes(needle) ||
      s.short.toLowerCase().includes(needle) ||
      s.ports.some((p) => `${p.port}/${p.protocol}`.includes(needle)),
  )
  return (
    <Card>
      <CardHeader>
        <CardTitle>Services</CardTitle>
        <CardDescription>{services.data.length} service definitions available to zones and rich rules.</CardDescription>
        <CardAction>
          <Input placeholder="Search name or port…" value={q} onChange={(e) => setQ(e.target.value)} className="h-8 w-56" />
        </CardAction>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Ports</TableHead>
              <TableHead>Description</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((s) => (
              <TableRow key={s.name}>
                <TableCell className="font-mono">{s.name}</TableCell>
                <TableCell className="font-mono text-xs">{s.ports.map((p) => `${p.port}/${p.protocol}`).join(', ')}</TableCell>
                <TableCell className="max-w-xl truncate text-xs text-muted-foreground" title={s.description}>
                  {s.short}
                  {s.description ? ` — ${s.description}` : ''}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
