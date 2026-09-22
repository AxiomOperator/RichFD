import { useQuery } from '@tanstack/react-query'
import { GlobeIcon, RefreshCwIcon, Trash2Icon } from 'lucide-react'
import { api } from '@/api/client'
import { useFwMutation } from '@/api/hooks'
import type { DdnsEntry } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { describe } from '@/lib/rule-form'
import { useCanEdit } from '@/lib/session'

export default function DdnsPage() {
  const canEdit = useCanEdit()
  const list = useQuery({ queryKey: ['ddns'], queryFn: () => api.get<DdnsEntry[]>('/ddns'), refetchInterval: 30_000 })
  const refresh = useFwMutation((id: string) => api.post<DdnsEntry>(`/ddns/${id}/refresh`), (_v, e) =>
    e.last_error ? `Resolution failed: ${e.last_error}` : `Resolved to ${(e.resolved ?? []).join(', ') || 'nothing'}`)
  const del = useFwMutation((id: string) => api.delete(`/ddns/${id}`), 'DDNS rule and its generated rules removed')
  if (list.isPending) return <Skeleton className="h-96 w-full" />
  if (list.isError) return <p className="text-destructive">{list.error.message}</p>
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><GlobeIcon className="size-5" /> Dynamic DNS rules</CardTitle>
        <CardDescription>
          Rich rules whose source is a hostname (e.g. myhome.dyndns.org). firewalld only accepts addresses, so RichFD
          resolves each name on a schedule and keeps one concrete rule per current address, replacing rules when the
          address changes. To create one, type a hostname as the source address in the rich rule builder.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Hostname</TableHead>
              <TableHead>Rule</TableHead>
              <TableHead>Where</TableHead>
              <TableHead>Currently resolves to</TableHead>
              <TableHead>Last check</TableHead>
              <TableHead className="w-24" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {list.data.map((e) => {
              const d = describe(e.template)
              return (
                <TableRow key={e.id}>
                  <TableCell className="font-mono text-sm">{e.hostname}</TableCell>
                  <TableCell className="text-xs">{d.element} → {d.action}</TableCell>
                  <TableCell className="text-xs">{e.scope} <span className="font-mono">{e.zone}</span></TableCell>
                  <TableCell className="font-mono text-xs">
                    {Object.keys(e.applied).join(', ') || '—'}
                    {e.last_error && <div className="font-sans text-destructive">{e.last_error}</div>}
                  </TableCell>
                  <TableCell className="text-xs">
                    {e.last_check ? new Date(e.last_check * 1000).toLocaleTimeString() : 'never'} · every {Math.round(e.interval / 60)} min
                  </TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    {canEdit && (
                      <>
                        <Button variant="ghost" size="icon-sm" aria-label="Resolve now" onClick={() => refresh.mutate(e.id)}><RefreshCwIcon /></Button>
                        <ConfirmButton size="icon-sm" destructive aria-label="Delete" title={`Delete DDNS rule for ${e.hostname}?`}
                          description="Also removes the rich rules generated for its current addresses." confirmLabel="Delete" onConfirm={() => del.mutate(e.id)}>
                          <Trash2Icon />
                        </ConfirmButton>
                      </>
                    )}
                  </TableCell>
                </TableRow>
              )
            })}
            {list.data.length === 0 && (
              <TableRow>
                <TableCell colSpan={6} className="py-8 text-center text-muted-foreground">
                  No DDNS rules. In a zone's rich rules, choose <Badge variant="outline">Source: Address</Badge> and type a hostname.
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </CardContent>
    </Card>
  )
}
