import { DownloadIcon, FileCode2Icon, FileUpIcon, UploadIcon } from 'lucide-react'
import { ExportCodeDialog, type ExportScope } from '@/components/ExportCode'
import { useState } from 'react'
import { toast } from 'sonner'
import { api, apiUrl } from '@/api/client'
import { useFwMutation, usePolicies, useZones } from '@/api/hooks'
import type { ImportPlanItem } from '@/api/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectGroup, SelectItem, SelectLabel, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { useCanEdit } from '@/lib/session'

const SECTIONS = ['zones', 'policies', 'services', 'ipsets'] as const

function ExportCard() {
  const zones = useZones()
  const policies = usePolicies()
  const [sections, setSections] = useState<string[]>([...SECTIONS])
  const [one, setOne] = useState('')
  const [kind, name] = one.split(':')
  return (
    <Card>
      <CardHeader>
        <CardTitle>Export</CardTitle>
        <CardDescription>Download the permanent configuration to back it up or copy it to another machine.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-6">
        <div className="grid gap-2">
          <Label>Whole configuration (richrule JSON)</Label>
          <div className="flex flex-wrap items-center gap-4">
            {SECTIONS.map((s) => (
              <label key={s} className="flex items-center gap-1.5 text-sm">
                <Checkbox checked={sections.includes(s)} onCheckedChange={(c) => setSections(c ? [...sections, s] : sections.filter((x) => x !== s))} />
                {s}
              </label>
            ))}
            <Button asChild size="sm" disabled={!sections.length}>
              <a href={apiUrl(`/export?format=json&sections=${sections.join(',')}`)} download><DownloadIcon /> Download JSON</a>
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">Services: only custom or locally modified ones are included.</p>
        </div>
        <div className="grid gap-2">
          <Label>One zone or policy</Label>
          <div className="flex flex-wrap items-center gap-2">
            <Select value={one} onValueChange={setOne}>
              <SelectTrigger size="sm" className="w-64" aria-label="Object"><SelectValue placeholder="Choose…" /></SelectTrigger>
              <SelectContent className="max-h-80">
                <SelectGroup>
                  <SelectLabel>Zones</SelectLabel>
                  {zones.data?.map((z) => <SelectItem key={z.name} value={`zone:${z.name}`}>{z.name}</SelectItem>)}
                </SelectGroup>
                <SelectGroup>
                  <SelectLabel>Policies</SelectLabel>
                  {policies.data?.map((p) => <SelectItem key={p.name} value={`policy:${p.name}`}>{p.name}</SelectItem>)}
                </SelectGroup>
              </SelectContent>
            </Select>
            <Button asChild size="sm" variant="outline" disabled={!one}>
              <a href={one ? apiUrl(`/export?format=xml&kind=${kind}&name=${encodeURIComponent(name)}`) : undefined} download>firewalld XML</a>
            </Button>
            <Button asChild size="sm" variant="outline" disabled={!one}>
              <a href={one ? apiUrl(`/export?format=json&kind=${kind}&name=${encodeURIComponent(name)}`) : undefined} download>JSON</a>
            </Button>
          </div>
        </div>
        <div className="grid gap-2">
          <Label>Raw /etc/firewalld</Label>
          <div>
            <Button asChild size="sm" variant="outline">
              <a href={apiUrl('/export?format=tar')} download><DownloadIcon /> Download .tar.gz</a>
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

function ImportCard() {
  const canEdit = useCanEdit()
  const [preview, setPreview] = useState<{ bundle: Record<string, unknown>; plan: ImportPlanItem[] } | null>(null)
  const [chosen, setChosen] = useState<Set<string>>(new Set())
  const [reload, setReload] = useState(false)
  const [busy, setBusy] = useState(false)
  const apply = useFwMutation(
    () => api.post<{ ok: boolean; results: { kind: string; name: string; result: string; error?: string }[] }>('/import/apply', {
      bundle: preview!.bundle,
      only: [...chosen],
      reload,
    }),
    (_v, r) => (r.ok ? `Imported ${r.results.length} object(s)` : 'Import finished with errors'),
  )

  async function onFile(file: File | undefined) {
    if (!file) return
    setBusy(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const p = await api.upload<{ bundle: Record<string, unknown>; plan: ImportPlanItem[] }>('/import/preview', form)
      setPreview(p)
      setChosen(new Set(p.plan.filter((x) => x.action !== 'unchanged').map((x) => `${x.kind}/${x.name}`)))
    } catch (e) {
      toast.error((e as Error).message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Import</CardTitle>
        <CardDescription>
          Upload a richrule JSON export or a firewalld XML file (zone, policy, service or IP set; the file name becomes
          the object name). You'll see what changes before anything is applied. Imports go to the permanent configuration.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <label className="flex cursor-pointer flex-col items-center gap-2 rounded-lg border-2 border-dashed p-6 text-sm text-muted-foreground hover:bg-muted/40">
          <FileUpIcon className="size-6" />
          {busy ? 'Reading…' : 'Choose a .json or .xml file'}
          <input type="file" accept=".json,.xml,application/json,application/xml" className="sr-only"
            onChange={(e) => onFile(e.target.files?.[0])} />
        </label>
        {preview && (
          <>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead className="w-8" />
                  <TableHead>Object</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Changed settings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {preview.plan.map((p) => {
                  const k = `${p.kind}/${p.name}`
                  return (
                    <TableRow key={k}>
                      <TableCell>
                        <Checkbox checked={chosen.has(k)} disabled={p.action === 'unchanged'}
                          onCheckedChange={(c) => setChosen((s) => { const n = new Set(s); if (c) n.add(k); else n.delete(k); return n })} />
                      </TableCell>
                      <TableCell className="font-mono text-xs">{k}</TableCell>
                      <TableCell>
                        <Badge variant={p.action === 'create' ? 'default' : p.action === 'update' ? 'secondary' : 'outline'}>{p.action}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{p.action === 'unchanged' ? '—' : p.changes.join(', ')}</TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
            {canEdit && (
              <div className="flex flex-wrap items-center gap-4">
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={reload} onCheckedChange={(c) => setReload(c === true)} /> Reload firewalld afterwards (activates the import, discards runtime-only changes)
                </label>
                <Button onClick={() => apply.mutateAsync(undefined).then(() => setPreview(null), () => {})} disabled={!chosen.size || apply.isPending}>
                  <UploadIcon /> Import {chosen.size} object{chosen.size === 1 ? '' : 's'}
                </Button>
              </div>
            )}
          </>
        )}
      </CardContent>
    </Card>
  )
}

function AutomationCard() {
  const zones = useZones()
  const policies = usePolicies()
  const [chosenZones, setChosenZones] = useState<string[] | null>(null)
  const [withPolicies, setWithPolicies] = useState(true)
  const [withServices, setWithServices] = useState(true)
  const [withIpsets, setWithIpsets] = useState(true)
  const [scope, setScope] = useState<ExportScope | null>(null)
  const all = zones.data?.map((z) => z.name) ?? []
  const picked = chosenZones ?? all
  return (
    <Card className="xl:col-span-2">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><FileCode2Icon className="size-5" /> Automation: Ansible / firewall-cmd</CardTitle>
        <CardDescription>
          Prototype here, then roll the same configuration out to many servers: generate an idempotent Ansible
          playbook (ansible.posix.firewalld) or a firewall-cmd script. Selected rules can also be exported from any
          zone's rich rules list.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-3">
        <div className="flex max-h-32 flex-wrap gap-x-4 gap-y-2 overflow-y-auto rounded-md border p-2">
          {all.map((z) => (
            <label key={z} className="flex items-center gap-1.5 text-sm">
              <Checkbox checked={picked.includes(z)} onCheckedChange={(c) => setChosenZones(c ? [...picked, z] : picked.filter((x) => x !== z))} />
              <span className="font-mono">{z}</span>
            </label>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-4 text-sm">
          <label className="flex items-center gap-1.5"><Checkbox checked={withPolicies} onCheckedChange={(c) => setWithPolicies(c === true)} /> policies ({policies.data?.length ?? 0})</label>
          <label className="flex items-center gap-1.5"><Checkbox checked={withServices} onCheckedChange={(c) => setWithServices(c === true)} /> custom services</label>
          <label className="flex items-center gap-1.5"><Checkbox checked={withIpsets} onCheckedChange={(c) => setWithIpsets(c === true)} /> IP sets</label>
          <Button size="sm" onClick={() => setScope({ zones: picked, policies: withPolicies ? null : [], services: withServices, ipsets: withIpsets })}>
            Generate
          </Button>
        </div>
      </CardContent>
      {scope && <ExportCodeDialog title="firewalld configuration" scope={scope} onClose={() => setScope(null)} />}
    </Card>
  )
}

export default function ImportExportPage() {
  return (
    <div className="grid gap-6 xl:grid-cols-2">
      <AutomationCard />
      <ExportCard />
      <ImportCard />
    </div>
  )
}
