import { RotateCcwIcon, Trash2Icon } from 'lucide-react'
import { useState } from 'react'
import { useNavigate, useParams } from 'react-router'
import { api } from '@/api/client'
import { useFwMutation, usePolicy } from '@/api/hooks'
import { ConfirmButton } from '@/components/ConfirmButton'
import {
  ForwardingTab,
  PolicyZonesTab,
  PortsTab,
  ProtocolsIcmpTab,
  RichRulesCard,
  ServicesTab,
} from '@/components/RuleSet'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Switch } from '@/components/ui/switch'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useCanEdit } from '@/lib/session'
import { mergeItems, useRuleOps } from '@/lib/zone-ops'
import { ExportMenu } from './Zone'

export default function PolicyPage() {
  const { name = '' } = useParams()
  const navigate = useNavigate()
  const policy = usePolicy(name)
  const ops = useRuleOps('policy', name)
  const [prio, setPrio] = useState<string | null>(null)
  const canEdit = useCanEdit()
  const update = useFwMutation(
    (fields: Record<string, unknown>) => api.patch(`/policies/${encodeURIComponent(name)}`, fields),
    'Saved to permanent config — reload to apply',
  )
  const del = useFwMutation(() => api.delete(`/policies/${encodeURIComponent(name)}`), `Policy ${name} removed`)

  if (policy.isPending) return <Skeleton className="h-96 w-full" />
  if (policy.isError) return <p className="text-destructive">{policy.error.message}</p>
  const runtime = policy.data.runtime ?? undefined
  const permanent = policy.data.permanent ?? undefined
  const view = permanent ?? runtime!
  const props = { runtime, permanent, ops }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold">{name}</h1>
            <Badge variant="outline">policy</Badge>
            {view.disable && <Badge variant="destructive">disabled</Badge>}
            {!runtime && <Badge variant="outline">permanent only — reload to activate</Badge>}
          </div>
          {view.short && <p className="text-sm font-medium">{view.short}</p>}
          {view.description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{view.description}</p>}
          <p className="mt-2 font-mono text-xs text-muted-foreground">
            {view.ingress_zones.join(', ') || '—'} → {view.egress_zones.join(', ') || '—'}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <label className="flex items-center gap-2">
            <span className="text-muted-foreground">Priority</span>
            <Input
              className="h-8 w-24"
              type="number"
              value={prio ?? String(view.priority)}
              onChange={(e) => setPrio(e.target.value)}
              onBlur={() => {
                if (prio !== null && Number(prio) !== view.priority) update.mutate({ priority: Number(prio) })
                setPrio(null)
              }}
              disabled={!permanent || !canEdit}
            />
          </label>
          <label className="flex items-center gap-2">
            <span className="text-muted-foreground">Target</span>
            <Select value={view.target} onValueChange={(target) => update.mutate({ target })} disabled={!permanent || !canEdit}>
              <SelectTrigger size="sm" className="w-32" aria-label="Policy target"><SelectValue /></SelectTrigger>
              <SelectContent>
                {['CONTINUE', 'ACCEPT', 'REJECT', 'DROP'].map((t) => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </label>
          <label className="flex items-center gap-2">
            <Switch checked={!view.disable} onCheckedChange={(on) => update.mutate({ disable: !on })} disabled={!permanent || !canEdit} />
            Enabled
          </label>
          <ExportMenu kind="policy" name={name} />
          {permanent && (!permanent.builtin || permanent.modified) && (
            <ConfirmButton
              variant="outline"
              size="sm"
              destructive
              title={permanent.builtin ? `Reset ${name} to defaults?` : `Delete policy ${name}?`}
              description="Changes the permanent configuration; reload to apply."
              confirmLabel={permanent.builtin ? 'Reset' : 'Delete'}
              onConfirm={() => del.mutateAsync(undefined).then(() => !permanent.builtin && navigate('/policies'), () => {})}
            >
              {permanent.builtin ? <><RotateCcwIcon /> Reset</> : <><Trash2Icon /> Delete</>}
            </ConfirmButton>
          )}
          {!permanent && <Button size="sm" variant="ghost" disabled>runtime only</Button>}
        </div>
      </div>
      <Tabs defaultValue="rich">
        <TabsList className="flex-wrap">
          <TabsTrigger value="rich">Rich rules ({mergeItems(runtime?.rich_rules, permanent?.rich_rules, (r) => r.rule).length})</TabsTrigger>
          <TabsTrigger value="zones">Zones</TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="protocols">Protocols &amp; ICMP</TabsTrigger>
          <TabsTrigger value="forwarding">Masquerade &amp; forwarding</TabsTrigger>
        </TabsList>
        <TabsContent value="rich" className="mt-4"><RichRulesCard {...props} /></TabsContent>
        <TabsContent value="zones" className="mt-4"><PolicyZonesTab {...props} /></TabsContent>
        <TabsContent value="services" className="mt-4"><ServicesTab {...props} /></TabsContent>
        <TabsContent value="ports" className="mt-4"><PortsTab {...props} /></TabsContent>
        <TabsContent value="protocols" className="mt-4"><ProtocolsIcmpTab {...props} /></TabsContent>
        <TabsContent value="forwarding" className="mt-4"><ForwardingTab {...props} /></TabsContent>
      </Tabs>
    </div>
  )
}
