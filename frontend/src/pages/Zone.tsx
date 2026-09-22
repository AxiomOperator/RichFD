import { DownloadIcon, RotateCcwIcon, StarIcon, Trash2Icon } from 'lucide-react'
import { useLocation, useNavigate, useParams } from 'react-router'
import { api, apiUrl } from '@/api/client'
import { useFwMutation, useStatus, useZone } from '@/api/hooks'
import { ConfirmButton } from '@/components/ConfirmButton'
import {
  BindingsTab,
  ForwardingTab,
  PortsTab,
  ProtocolsIcmpTab,
  RichRulesCard,
  ServicesTab,
  type RuleDraft,
} from '@/components/RuleSet'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useRiskCheck } from '@/lib/risk'
import { useCanEdit } from '@/lib/session'
import { mergeItems, useRuleOps } from '@/lib/zone-ops'

const TARGETS = [
  { value: 'default', label: 'default (reject)' },
  { value: 'ACCEPT', label: 'ACCEPT' },
  { value: 'DROP', label: 'DROP' },
  { value: '%%REJECT%%', label: 'REJECT' },
]

export function ExportMenu({ kind, name }: { kind: 'zone' | 'policy' | 'service' | 'ipset'; name: string }) {
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <DownloadIcon /> Export
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem asChild>
          <a href={apiUrl(`/export?format=xml&kind=${kind}&name=${encodeURIComponent(name)}`)} download>
            firewalld XML
          </a>
        </DropdownMenuItem>
        <DropdownMenuItem asChild>
          <a href={apiUrl(`/export?format=json&kind=${kind}&name=${encodeURIComponent(name)}`)} download>
            richrule JSON
          </a>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

export default function ZonePage() {
  const { name = '' } = useParams()
  const navigate = useNavigate()
  const location = useLocation()
  const draft = (location.state as { draft?: RuleDraft } | null)?.draft ?? null
  const zone = useZone(name)
  const status = useStatus()
  const ops = useRuleOps('zone', name)
  const checkRisk = useRiskCheck()
  const canEdit = useCanEdit()
  const setTarget = useFwMutation(
    (target: string) => api.patch(`/zones/${encodeURIComponent(name)}`, { target }),
    'Zone target saved to permanent config — reload to apply',
  )
  const setDefault = useFwMutation(() => api.post('/default-zone', { zone: name }), `Default zone set to ${name}`)
  const del = useFwMutation(() => api.delete(`/zones/${encodeURIComponent(name)}`), `Zone ${name} deleted`)
  const reset = useFwMutation(
    () => api.post(`/zones/${encodeURIComponent(name)}/reset`),
    `Zone ${name} reset to defaults in permanent config — reload to apply`,
  )

  if (zone.isPending) return <Skeleton className="h-96 w-full" />
  if (zone.isError) return <p className="text-destructive">{zone.error.message}</p>

  const runtime = zone.data.runtime ?? undefined
  const permanent = zone.data.permanent ?? undefined
  const view = permanent ?? runtime!
  const isDefault = status.data?.default_zone === name
  const active = status.data?.active_zones[name]
  const props = { runtime, permanent, ops }

  async function changeTarget(t: string) {
    const d = await checkRisk({ target: 'permanent', zone_target: { zone: name, target: t } })
    if (d.proceed) setTarget.mutate(t)
  }

  return (
    <div className="grid gap-6">
      <div className="flex flex-wrap items-start gap-4">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-2xl font-semibold">{name}</h1>
            {isDefault && <Badge>default</Badge>}
            {active ? <Badge variant="secondary">active</Badge> : <Badge variant="outline">inactive</Badge>}
            {!runtime && <Badge variant="outline">permanent only — reload to activate</Badge>}
            {!permanent && <Badge variant="secondary">runtime only</Badge>}
          </div>
          {view.short && view.short !== name && <p className="text-sm font-medium">{view.short}</p>}
          {view.description && <p className="mt-1 max-w-3xl text-sm text-muted-foreground">{view.description}</p>}
          {active && (
            <p className="mt-2 text-xs text-muted-foreground">
              Bound to: {[...active.interfaces, ...active.sources].join(', ') || '—'}
            </p>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-2 text-sm">
            <span className="text-muted-foreground">Target</span>
            <Select value={permanent?.target ?? runtime?.target} onValueChange={changeTarget} disabled={!permanent || !canEdit}>
              <SelectTrigger size="sm" className="w-40" aria-label="Zone target">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {TARGETS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <ExportMenu kind="zone" name={name} />
          {canEdit && !isDefault && runtime && (
            <Button variant="outline" size="sm" onClick={() => setDefault.mutate(undefined)}>
              <StarIcon /> Make default
            </Button>
          )}
          {permanent?.builtin && permanent.modified && (
            <ConfirmButton
              variant="outline"
              size="sm"
              destructive
              title={`Reset ${name} to defaults?`}
              description="Discards all customizations of this built-in zone in the permanent configuration (services, ports, rich rules, bindings). Reload to apply."
              confirmLabel="Reset zone"
              onConfirm={() => reset.mutate(undefined)}
            >
              <RotateCcwIcon /> Reset to defaults
            </ConfirmButton>
          )}
          {permanent && !permanent.builtin && !isDefault && (
            <ConfirmButton
              variant="outline"
              size="sm"
              destructive
              title={`Delete zone ${name}?`}
              description="Removes the zone from the permanent configuration. Reload to apply."
              confirmLabel="Delete zone"
              onConfirm={() => del.mutateAsync(undefined).then(() => navigate('/'), () => {})}
            >
              <Trash2Icon /> Delete
            </ConfirmButton>
          )}
        </div>
      </div>
      {runtime && permanent && runtime.target !== permanent.target && (
        <p className="text-xs text-amber-700 dark:text-amber-400">
          Target differs: runtime {runtime.target}, permanent {permanent.target}. Reload to apply.
        </p>
      )}

      <Tabs defaultValue="rich">
        <TabsList className="flex-wrap">
          <TabsTrigger value="rich">
            Rich rules ({mergeItems(runtime?.rich_rules, permanent?.rich_rules, (r) => r.rule).length})
          </TabsTrigger>
          <TabsTrigger value="services">Services</TabsTrigger>
          <TabsTrigger value="ports">Ports</TabsTrigger>
          <TabsTrigger value="protocols">Protocols &amp; ICMP</TabsTrigger>
          <TabsTrigger value="forwarding">Forwarding &amp; NAT</TabsTrigger>
          <TabsTrigger value="bindings">Interfaces &amp; sources</TabsTrigger>
        </TabsList>
        <TabsContent value="rich" className="mt-4">
          <RichRulesCard {...props} draft={draft} onDraftConsumed={() => navigate(location.pathname, { replace: true, state: null })} />
        </TabsContent>
        <TabsContent value="services" className="mt-4">
          <ServicesTab {...props} />
        </TabsContent>
        <TabsContent value="ports" className="mt-4">
          <PortsTab {...props} />
        </TabsContent>
        <TabsContent value="protocols" className="mt-4">
          <ProtocolsIcmpTab {...props} />
        </TabsContent>
        <TabsContent value="forwarding" className="mt-4">
          <ForwardingTab {...props} />
        </TabsContent>
        <TabsContent value="bindings" className="mt-4">
          <BindingsTab {...props} />
        </TabsContent>
      </Tabs>
    </div>
  )
}
