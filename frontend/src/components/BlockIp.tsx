import { BanIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { useApplyOps, useStatus, useZones } from '@/api/hooks'
import { Button } from '@/components/ui/button'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { useApplyMode } from '@/lib/apply-mode'
import { useRiskCheck } from '@/lib/risk'
import { useCanEdit } from '@/lib/session'

/** "Block this IP": a priority -100 drop rich rule, optionally killing existing connections. */
export function BlockIpButton({ ip, zone, allowTerminate }: { ip: string; zone?: string; allowTerminate?: boolean }) {
  const canEdit = useCanEdit()
  const [open, setOpen] = useState(false)
  if (!canEdit) return null
  return (
    <>
      <Tooltip>
        <TooltipTrigger asChild>
          <Button variant="ghost" size="icon-sm" aria-label={`Block ${ip}`} onClick={() => setOpen(true)}>
            <BanIcon className="text-destructive" />
          </Button>
        </TooltipTrigger>
        <TooltipContent>Block {ip}</TooltipContent>
      </Tooltip>
      {open && <BlockIpDialog ip={ip} zone={zone} allowTerminate={allowTerminate} onClose={() => setOpen(false)} />}
    </>
  )
}

function BlockIpDialog({ ip, zone, allowTerminate, onClose }: { ip: string; zone?: string; allowTerminate?: boolean; onClose: () => void }) {
  const zones = useZones()
  const status = useStatus()
  const { target, safe } = useApplyMode()
  const checkRisk = useRiskCheck()
  const apply = useApplyOps()
  const [z, setZ] = useState(zone || '')
  const [action, setAction] = useState<'drop' | 'reject'>('drop')
  const [kill, setKill] = useState(true)
  const chosen = z || status.data?.default_zone || ''
  const fam = ip.includes(':') ? 'ipv6' : 'ipv4'
  const rule = `rule priority="-100" family="${fam}" source address="${ip}" ${action}`
  const active = Object.keys(status.data?.active_zones ?? {})

  async function submit() {
    const ops = [{ action: 'add' as const, kind: 'rich-rule' as const, zone: chosen, value: { rule }, scope: 'zone' as const }]
    const d = await checkRisk({ ops, target })
    if (!d.proceed) return
    try {
      await apply.mutateAsync({ ops, target, safe: (safe || d.safe) && target !== 'permanent' })
      if (allowTerminate && kill) {
        const r = await api.post<{ sockets_closed?: number; conntrack_deleted?: number; ss_error?: string }>('/connections/terminate', { ip })
        if (r.ss_error) toast.warning(`Rule added; could not close existing connections: ${r.ss_error}`)
        else toast.success(`Closed ${r.sockets_closed ?? 0} connection(s)`)
      }
      onClose()
    } catch {
      /* toast shown */
    }
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Block {ip}</DialogTitle>
          <DialogDescription>Adds a high-priority rich rule so it wins over services and other allow rules.</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          <div className="grid grid-cols-2 gap-3">
            <div className="grid gap-1.5">
              <Label>Zone</Label>
              <Select value={chosen} onValueChange={setZ}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent className="max-h-72">
                  {zones.data?.map((zz) => (
                    <SelectItem key={zz.name} value={zz.name}>
                      {zz.name}{active.includes(zz.name) ? ' (active)' : ''}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="grid gap-1.5">
              <Label>Action</Label>
              <Select value={action} onValueChange={(v) => setAction(v as 'drop' | 'reject')}>
                <SelectTrigger className="w-full"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="drop">drop (silent)</SelectItem>
                  <SelectItem value="reject">reject (send refusal)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <code className="rounded-md bg-muted p-2 text-xs break-all">{rule}</code>
          {allowTerminate && (
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={kill} onCheckedChange={(c) => setKill(c === true)} />
              Also close existing connections (established flows are otherwise still allowed)
            </label>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button variant="destructive" onClick={submit} disabled={!chosen || apply.isPending}>Block</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
