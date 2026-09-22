import { WandSparklesIcon } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { useFwMutation, useServices, useTemplates, useZones } from '@/api/hooks'
import type { Op, Template } from '@/api/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { TARGET_LABELS, useApplyMode } from '@/lib/apply-mode'
import { useRiskCheck } from '@/lib/risk'
import { useCanEdit } from '@/lib/session'

type Preview = { title: string; steps: string[]; notes: string[]; ops: Op[] }

function TemplateDialog({ t, onClose }: { t: Template; onClose: () => void }) {
  const zones = useZones()
  const services = useServices()
  const { target } = useApplyMode()
  const checkRisk = useRiskCheck()
  const [params, setParams] = useState<Record<string, string | boolean>>(() =>
    Object.fromEntries(t.params.map((p) => [p.name, p.default ?? (p.type === 'bool' ? false : '')])),
  )
  const [preview, setPreview] = useState<Preview | null>(null)
  const apply = useFwMutation(
    () => api.post<{ done: string[] }>('/templates/apply', { template: t.id, params, target }),
    (_v, r) => `${t.title}: ${r.done.length} step(s) applied`,
  )
  const set = (k: string, v: string | boolean) => {
    setParams((p) => ({ ...p, [k]: v }))
    setPreview(null)
  }

  async function doPreview() {
    try {
      setPreview(await api.post<Preview>('/templates/preview', { template: t.id, params }))
    } catch (e) {
      toast.error((e as Error).message)
    }
  }

  async function doApply() {
    if (!preview) return
    const d = await checkRisk({ ops: preview.ops, target })
    if (!d.proceed) return
    apply.mutateAsync(undefined).then(onClose, () => {})
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[92svh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>{t.title}</DialogTitle>
          <DialogDescription>{t.description}</DialogDescription>
        </DialogHeader>
        <div className="grid gap-3">
          {t.params.map((p) => (
            <div key={p.name} className={p.type === 'bool' ? '' : 'grid gap-1.5'}>
              {p.type === 'bool' ? (
                <label className="flex items-center gap-2 text-sm">
                  <Checkbox checked={params[p.name] === true} onCheckedChange={(c) => set(p.name, c === true)} /> {p.label}
                </label>
              ) : (
                <>
                  <Label>{p.label}</Label>
                  {p.type === 'zone' || p.type === 'service' || p.type === 'select' ? (
                    <Select value={String(params[p.name] ?? '')} onValueChange={(v) => set(p.name, v)}>
                      <SelectTrigger className="w-full"><SelectValue placeholder="Choose…" /></SelectTrigger>
                      <SelectContent className="max-h-80">
                        {(p.type === 'zone' ? zones.data?.map((z) => z.name) : p.type === 'service' ? services.data?.map((s) => s.name) : p.options)?.map((o) => (
                          <SelectItem key={o} value={o}>{o}</SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  ) : p.type === 'textarea' ? (
                    <Textarea rows={4} className="font-mono text-xs" value={String(params[p.name] ?? '')} onChange={(e) => set(p.name, e.target.value)} />
                  ) : (
                    <Input value={String(params[p.name] ?? '')} placeholder={p.placeholder} onChange={(e) => set(p.name, e.target.value)} />
                  )}
                </>
              )}
            </div>
          ))}
        </div>
        {preview && (
          <div className="grid gap-2 rounded-md border bg-muted/40 p-3 text-sm">
            <div className="font-medium">This will ({TARGET_LABELS[target].toLowerCase()} unless noted):</div>
            <ol className="list-inside list-decimal font-mono text-xs break-all">{preview.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            {preview.notes.map((n, i) => <p key={i} className="text-xs text-muted-foreground">{n}</p>)}
          </div>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          {!preview ? (
            <Button onClick={doPreview}>Preview</Button>
          ) : (
            <Button onClick={doApply} disabled={apply.isPending}>Apply</Button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

export default function TemplatesPage() {
  const templates = useTemplates()
  const canEdit = useCanEdit()
  const [open, setOpen] = useState<Template | null>(null)
  if (templates.isPending) return <Skeleton className="h-96 w-full" />
  if (templates.isError) return <p className="text-destructive">{templates.error.message}</p>
  return (
    <div className="grid gap-4">
      <div>
        <h1 className="text-2xl font-semibold">Rule templates</h1>
        <p className="text-sm text-muted-foreground">Common recipes. Each one shows exactly what it will change before applying.</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {templates.data.map((t) => (
          <Card key={t.id} className="flex flex-col">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base"><WandSparklesIcon className="size-4 text-muted-foreground" />{t.title}</CardTitle>
              <CardDescription>{t.description}</CardDescription>
            </CardHeader>
            <CardContent className="flex-1" />
            <CardFooter>
              <Button size="sm" onClick={() => setOpen(t)} disabled={!canEdit}>Use template</Button>
            </CardFooter>
          </Card>
        ))}
      </div>
      {open && <TemplateDialog t={open} onClose={() => setOpen(null)} />}
    </div>
  )
}
