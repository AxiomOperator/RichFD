import { CopyIcon, DownloadIcon, FileCode2Icon } from 'lucide-react'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import { Button } from '@/components/ui/button'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs'

export interface ExportScope {
  zones?: string[] | null
  policies?: string[] | null
  services?: boolean
  ipsets?: boolean
  rules?: string[]
  scope?: 'zone' | 'policy'
  name?: string
}

/** Show the configuration as an Ansible playbook or firewall-cmd script, ready to copy. */
export function ExportCodeDialog({ title, scope, onClose }: { title: string; scope: ExportScope; onClose: () => void }) {
  const [format, setFormat] = useState<'ansible' | 'bash'>('ansible')
  const [result, setResult] = useState<{ content: string; filename: string } | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    let cancelled = false
    api
      .post<{ content: string; filename: string }>('/automation/export', { format, ...scope })
      .then((r) => !cancelled && (setResult(r), setError('')), (e: Error) => !cancelled && setError(e.message))
    return () => {
      cancelled = true
    }
  }, [format, scope])

  function download() {
    if (!result) return
    const url = URL.createObjectURL(new Blob([result.content], { type: 'text/plain' }))
    const a = Object.assign(document.createElement('a'), { href: url, download: result.filename })
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[92svh] sm:max-w-4xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2"><FileCode2Icon className="size-5" /> {title}</DialogTitle>
          <DialogDescription>
            Deploy the same configuration to other servers. Additive and idempotent: re-running it changes nothing,
            and nothing is removed from the targets. Built from the permanent configuration.
          </DialogDescription>
        </DialogHeader>
        <div className="flex flex-wrap items-center gap-2">
          <Tabs value={format} onValueChange={(v) => setFormat(v as 'ansible' | 'bash')}>
            <TabsList>
              <TabsTrigger value="ansible">Ansible playbook</TabsTrigger>
              <TabsTrigger value="bash">firewall-cmd script</TabsTrigger>
            </TabsList>
          </Tabs>
          <div className="ml-auto flex gap-2">
            <Button size="sm" variant="outline" disabled={!result}
              onClick={() => result && navigator.clipboard.writeText(result.content).then(() => toast.success('Copied'))}>
              <CopyIcon /> Copy
            </Button>
            <Button size="sm" variant="outline" disabled={!result} onClick={download}><DownloadIcon /> Download</Button>
          </div>
        </div>
        {format === 'ansible' && (
          <p className="text-xs text-muted-foreground">
            Needs the ansible.posix collection. Run with: <code>ansible-playbook -i inventory firewalld.yml</code>
          </p>
        )}
        {error ? (
          <p className="text-sm text-destructive">{error}</p>
        ) : (
          <pre className="max-h-[55svh] overflow-auto rounded-md border bg-muted/40 p-3 text-xs leading-5">{result?.content ?? 'Generating…'}</pre>
        )}
      </DialogContent>
    </Dialog>
  )
}
