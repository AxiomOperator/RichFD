import { ShieldAlertIcon } from 'lucide-react'
import { api } from '@/api/client'
import { useFwMutation, usePending } from '@/api/hooks'
import { Button } from '@/components/ui/button'

/** Banner for a safe-apply change awaiting confirmation, with a live countdown. */
export function PendingChangesBar() {
  const pending = usePending()
  const confirm = useFwMutation((id: string) => api.post(`/safe-apply/${id}/confirm`), 'Change confirmed')
  const revert = useFwMutation((id: string) => api.post(`/safe-apply/${id}/revert`), 'Change reverted')
  const p = pending.data
  if (!p) return null

  return (
    <div className="flex flex-wrap items-center gap-3 border-b border-amber-500/40 bg-amber-500/10 px-4 py-2.5 text-sm">
      <ShieldAlertIcon className="size-4 shrink-0 text-amber-600" />
      <div className="min-w-0 flex-1">
        <span className="font-medium">Safe apply:</span>{' '}
        {p.ops.map((o) => `${o.action} ${o.kind} ${Object.values(o.value).filter(Boolean).join(' ')}`).join('; ')}
        <span className="text-muted-foreground">
          {' '}
          — reverts in <span className="font-mono tabular-nums">{p.seconds_left}s</span> unless confirmed
          {p.persist ? ' (will also be saved to permanent)' : ''}.
        </span>
      </div>
      <Button size="sm" onClick={() => confirm.mutate(p.id)} disabled={confirm.isPending}>
        Keep change
      </Button>
      <Button size="sm" variant="outline" onClick={() => revert.mutate(p.id)} disabled={revert.isPending}>
        Revert now
      </Button>
    </div>
  )
}
