import { useQuery } from '@tanstack/react-query'
import { GitCompareIcon, RefreshCwIcon, RotateCcwIcon, ScanSearchIcon } from 'lucide-react'
import { useState } from 'react'
import { api } from '@/api/client'
import { useFwMutation, useHistory } from '@/api/hooks'
import type { HistoryEntry } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { DiffView } from '@/components/DiffView'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useCanEdit } from '@/lib/session'

function Detail({ entry, isLatest }: { entry: HistoryEntry; isLatest: boolean }) {
  const canEdit = useCanEdit()
  const [mode, setMode] = useState<'change' | 'compare'>('change')
  const diff = useQuery({
    queryKey: ['history', entry.id, mode],
    queryFn: () => api.get<{ diff: string }>(`/history/${entry.id}${mode === 'compare' ? '/compare' : ''}`),
  })
  const restore = useFwMutation(() => api.post(`/history/${entry.id}/restore`), `Restored snapshot ${entry.short} and reloaded firewalld`)
  return (
    <Card className="min-w-0">
      <CardHeader>
        <CardTitle className="text-base">{entry.message}</CardTitle>
        <CardDescription>
          {new Date(entry.date).toLocaleString()} · {entry.external ? 'made outside richrule' : entry.author} ·{' '}
          <span className="font-mono">{entry.short}</span>
        </CardDescription>
        {canEdit && !isLatest && (
          <CardAction>
            <ConfirmButton
              variant="outline"
              size="sm"
              title={`Restore snapshot ${entry.short}?`}
              description="Replaces /etc/firewalld with this snapshot and reloads firewalld. Runtime-only changes are discarded. The current state is snapshotted first, so this can be undone."
              confirmLabel="Restore"
              onConfirm={() => restore.mutate(undefined)}
            >
              <RotateCcwIcon /> Restore
            </ConfirmButton>
          </CardAction>
        )}
      </CardHeader>
      <CardContent className="grid gap-3">
        <Tabs value={mode} onValueChange={(v) => setMode(v as 'change' | 'compare')}>
          <TabsList>
            <TabsTrigger value="change">What this change did</TabsTrigger>
            <TabsTrigger value="compare" disabled={isLatest}>
              <GitCompareIcon /> Restore preview
            </TabsTrigger>
          </TabsList>
        </Tabs>
        {mode === 'compare' && (
          <p className="text-xs text-muted-foreground">Differences between the current configuration and this snapshot (what restoring would change).</p>
        )}
        {diff.isPending ? <Skeleton className="h-40" /> : diff.isError ? <p className="text-destructive">{diff.error.message}</p> : <DiffView diff={diff.data.diff} />}
      </CardContent>
    </Card>
  )
}

export default function HistoryPage() {
  const history = useHistory()
  const [selected, setSelected] = useState<string | null>(null)
  const check = useFwMutation(
    () => api.post<{ found: unknown }>('/history/check'),
    (_v, r) => (r.found ? 'Outside changes found and recorded' : 'No outside changes'),
  )

  if (history.isPending) return <Skeleton className="h-96 w-full" />
  if (history.isError) return <p className="text-destructive">{history.error.message}</p>
  const h = history.data
  if (!h.enabled)
    return (
      <Card>
        <CardHeader>
          <CardTitle>Config history unavailable</CardTitle>
          <CardDescription>
            Snapshots need git and read access to {h.firewalld_dir}. Run richrule as root (the systemd service does).
            Runtime changes made outside richrule are still detected and appear in the audit log.
          </CardDescription>
        </CardHeader>
      </Card>
    )
  const current = h.entries.find((e) => e.id === selected) ?? h.entries[0]

  return (
    <div className="grid gap-4 lg:grid-cols-[minmax(18rem,26rem)_1fr]">
      <Card className="self-start">
        <CardHeader>
          <CardTitle>Config history</CardTitle>
          <CardDescription>
            Snapshot of {h.firewalld_dir} after every change. Outside changes are checked every {h.watch_interval}s.
          </CardDescription>
          <CardAction className="flex gap-1">
            <Button variant="ghost" size="icon-sm" aria-label="Refresh" onClick={() => history.refetch()}>
              <RefreshCwIcon />
            </Button>
            <Button variant="ghost" size="icon-sm" aria-label="Check for outside changes now" onClick={() => check.mutate(undefined)}>
              <ScanSearchIcon />
            </Button>
          </CardAction>
        </CardHeader>
        <CardContent className="max-h-[70svh] overflow-y-auto px-2">
          <ul className="grid gap-1">
            {h.entries.map((e, i) => (
              <li key={e.id}>
                <button
                  onClick={() => setSelected(e.id)}
                  className={`w-full rounded-md px-3 py-2 text-left text-sm hover:bg-muted ${current?.id === e.id ? 'bg-muted' : ''}`}
                >
                  <div className="flex items-center gap-2">
                    <span className="line-clamp-2 flex-1 font-medium">{e.message}</span>
                    {i === 0 && <Badge variant="secondary">current</Badge>}
                    {e.external && <Badge variant="destructive">outside</Badge>}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {new Date(e.date).toLocaleString()} · {e.author} {e.stat && `· ${e.stat.replace(/ changed,?/, '')}`}
                  </div>
                </button>
              </li>
            ))}
          </ul>
        </CardContent>
      </Card>
      {current ? (
        <Detail key={current.id} entry={current} isLatest={current.id === h.entries[0]?.id} />
      ) : (
        <p className="text-sm text-muted-foreground">No snapshots yet.</p>
      )}
    </div>
  )
}
