import { useQuery } from '@tanstack/react-query'
import { ArchiveIcon, DownloadIcon, EyeIcon, RotateCcwIcon, Trash2Icon, UploadIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, apiUrl } from '@/api/client'
import { useFwMutation } from '@/api/hooks'
import type { Backup, ImportPlanItem } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardAction, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useCanEdit } from '@/lib/session'

interface Inspect {
  files: string[]
  changes: { file: string; change: 'added' | 'modified' | 'removed' }[]
  plan?: ImportPlanItem[]
}

function InspectDialog({ b, onClose }: { b: Backup; onClose: () => void }) {
  const info = useQuery({ queryKey: ['backup', b.id], queryFn: () => api.get<Inspect>(`/backups/${b.id}`) })
  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90svh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>{b.name}</DialogTitle>
          <DialogDescription>What restoring this backup would change.</DialogDescription>
        </DialogHeader>
        {info.isPending ? <Skeleton className="h-40" /> : info.isError ? <p className="text-destructive">{info.error.message}</p> : (
          <div className="grid gap-3 text-sm">
            {info.data.files.length > 0 ? (
              <>
                <p>{info.data.files.length} files in the backup; {info.data.changes.length} differ from the current configuration.</p>
                <ul className="divide-y rounded-md border">
                  {info.data.changes.map((c) => (
                    <li key={c.file} className="flex items-center justify-between px-3 py-1.5 font-mono text-xs">
                      {c.file}
                      <Badge variant={c.change === 'removed' ? 'destructive' : c.change === 'added' ? 'default' : 'secondary'}>
                        {c.change === 'removed' ? 'will be removed' : c.change === 'added' ? 'will be added' : 'will change'}
                      </Badge>
                    </li>
                  ))}
                  {info.data.changes.length === 0 && <li className="px-3 py-2 text-muted-foreground">Identical to the current configuration.</li>}
                </ul>
              </>
            ) : (
              <ul className="divide-y rounded-md border">
                {info.data.plan?.map((p) => (
                  <li key={`${p.kind}/${p.name}`} className="flex items-center justify-between px-3 py-1.5 font-mono text-xs">
                    {p.kind}/{p.name}
                    <Badge variant={p.action === 'unchanged' ? 'outline' : 'secondary'}>{p.action}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  )
}

const size = (n: number) => (n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1e3))} kB`)

export default function BackupsPage() {
  const canEdit = useCanEdit()
  const list = useQuery({ queryKey: ['backups'], queryFn: () => api.get<{ backups: Backup[]; settings: { auto: boolean; interval_hours: number; keep: number } }>('/backups') })
  const [name, setName] = useState('')
  const [inspecting, setInspecting] = useState<Backup | null>(null)
  const create = useFwMutation(() => api.post<Backup>('/backups', { name }), (_v, b) => `Backup ${b.name} created`)
  const restore = useFwMutation((id: string) => api.post<{ mode: string }>(`/backups/${id}/restore`), (_v, r) =>
    r.mode === 'files' ? 'Configuration files restored and firewalld reloaded' : 'Objects imported and firewalld reloaded')
  const del = useFwMutation((id: string) => api.delete(`/backups/${id}`), 'Backup deleted')
  const setSettings = useFwMutation((v: Record<string, unknown>) => api.put('/backups/settings', v), 'Saved')

  async function upload(file?: File) {
    if (!file) return
    const form = new FormData()
    form.append('file', file)
    try {
      const b = await api.upload<Backup>('/backups/upload', form)
      toast.success(`Uploaded as "${b.name}" — review, then restore`)
      list.refetch()
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  if (list.isPending) return <Skeleton className="h-96 w-full" />
  if (list.isError) return <p className="text-destructive">{list.error.message}</p>
  const s = list.data.settings
  return (
    <div className="grid gap-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2"><ArchiveIcon className="size-5" /> Backups</CardTitle>
          <CardDescription>
            Full snapshots of the permanent configuration you can download and restore. Each contains the raw
            /etc/firewalld tree (when RichFD runs as root) plus a JSON export. Restoring snapshots the current state in
            Config history first, so a restore can be undone too.
          </CardDescription>
          {canEdit && (
            <CardAction className="flex gap-2">
              <form className="flex gap-2" onSubmit={(e) => { e.preventDefault(); create.mutateAsync(undefined).then(() => setName(''), () => {}) }}>
                <Input className="h-8 w-48" placeholder="name (e.g. before VPN setup)" value={name} onChange={(e) => setName(e.target.value)} maxLength={60} />
                <Button size="sm" type="submit" disabled={create.isPending}>Create backup</Button>
              </form>
              <Button size="sm" variant="outline" asChild>
                <label className="cursor-pointer">
                  <UploadIcon /> Upload
                  <input type="file" accept=".gz,.tgz,.tar,.json" className="sr-only" onChange={(e) => upload(e.target.files?.[0])} />
                </label>
              </Button>
            </CardAction>
          )}
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Contents</TableHead>
                <TableHead>Size</TableHead>
                <TableHead className="w-40" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.data.backups.map((b) => (
                <TableRow key={b.id}>
                  <TableCell>
                    <div className="font-medium">{b.name}</div>
                    <div className="text-xs text-muted-foreground">
                      {b.source === 'auto' ? 'automatic' : b.source === 'upload' ? 'uploaded' : `by ${b.user}`}{b.host ? ` · ${b.host}` : ''}
                    </div>
                  </TableCell>
                  <TableCell className="text-xs">{b.created ? new Date(b.created).toLocaleString() : '—'}</TableCell>
                  <TableCell className="space-x-1">
                    {b.has_files ? <Badge>files</Badge> : <Badge variant="outline">JSON only</Badge>}
                    {b.zones !== undefined && <span className="text-xs text-muted-foreground">{b.zones} zones · {b.policies} policies</span>}
                  </TableCell>
                  <TableCell className="text-xs">{size(b.size)}</TableCell>
                  <TableCell className="text-right whitespace-nowrap">
                    <Button variant="ghost" size="icon-sm" aria-label="Inspect" onClick={() => setInspecting(b)}><EyeIcon /></Button>
                    <Button variant="ghost" size="icon-sm" aria-label="Download" asChild>
                      <a href={apiUrl(`/backups/${b.id}/download`)} download><DownloadIcon /></a>
                    </Button>
                    <ConfirmButton size="icon-sm" aria-label="Restore" title={`Restore "${b.name}"?`}
                      description={b.has_files ? 'Replaces /etc/firewalld with this backup and reloads firewalld. Runtime-only changes are discarded.' : 'Imports the zones, policies, services and IP sets from this backup (replacing objects with the same name) and reloads firewalld.'}
                      confirmLabel="Restore" onConfirm={() => restore.mutate(b.id)}>
                      <RotateCcwIcon />
                    </ConfirmButton>
                    <ConfirmButton size="icon-sm" destructive aria-label="Delete" title={`Delete backup "${b.name}"?`} confirmLabel="Delete" onConfirm={() => del.mutate(b.id)}>
                      <Trash2Icon />
                    </ConfirmButton>
                  </TableCell>
                </TableRow>
              ))}
              {list.data.backups.length === 0 && (
                <TableRow><TableCell colSpan={5} className="py-8 text-center text-muted-foreground">No backups yet.</TableCell></TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>Automatic backups</CardTitle>
          <CardDescription>Taken in the background; the oldest automatic backups beyond the limit are deleted.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap items-center gap-6 text-sm">
          <label className="flex items-center gap-2">
            <Switch checked={s.auto} disabled={!canEdit} onCheckedChange={(auto) => setSettings.mutate({ auto })} /> Enabled
          </label>
          <label className="flex items-center gap-2">
            Every
            <Input className="h-8 w-20" type="number" min={1} defaultValue={s.interval_hours} disabled={!canEdit}
              onBlur={(e) => Number(e.target.value) !== s.interval_hours && setSettings.mutate({ interval_hours: Number(e.target.value) })} />
            hours
          </label>
          <label className="flex items-center gap-2">
            Keep
            <Input className="h-8 w-20" type="number" min={1} defaultValue={s.keep} disabled={!canEdit}
              onBlur={(e) => Number(e.target.value) !== s.keep && setSettings.mutate({ keep: Number(e.target.value) })} />
            backups
          </label>
        </CardContent>
      </Card>
      {inspecting && <InspectDialog b={inspecting} onClose={() => setInspecting(null)} />}
    </div>
  )
}
