import { AlertTriangleIcon, ShieldAlertIcon } from 'lucide-react'
import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react'
import { toast } from 'sonner'
import { api } from '@/api/client'
import type { Op, RiskResult, Target } from '@/api/types'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog'
import { Checkbox } from '@/components/ui/checkbox'
import { Label } from '@/components/ui/label'

export interface RiskDecision {
  proceed: boolean
  /** Apply with safe apply (auto-revert) regardless of the global setting. */
  safe: boolean
}

type Check = (req: { ops?: Op[]; target: Target; zone_target?: { zone: string; target: string } }) => Promise<RiskDecision>

const Ctx = createContext<Check | null>(null)

/** Asks the backend whether a change could lock someone out, and confirms with the user if so. */
export function RiskProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ risk: RiskResult; target: Target } | null>(null)
  const [safe, setSafe] = useState(true)
  const resolver = useRef<((d: RiskDecision) => void) | null>(null)

  const check = useCallback<Check>(async (req) => {
    let risk: RiskResult
    // Only show a spinner if the check is slow.
    let toastId: string | number | undefined
    const timer = setTimeout(() => (toastId = toast.loading('Checking for lock-out risks…')), 400)
    try {
      risk = await api.post<RiskResult>('/risk', { ops: req.ops ?? [], target: req.target, zone_target: req.zone_target })
    } catch (e) {
      // Fail safe: if the check itself fails, ask before applying and suggest safe apply.
      risk = {
        level: 'warning',
        warnings: [{ level: 'warning', message: `The lock-out check could not run (${(e as Error).message}).` }],
        connections: [],
        force_safe: false,
      }
    } finally {
      clearTimeout(timer)
      if (toastId !== undefined) toast.dismiss(toastId)
    }
    if (risk.level === 'ok') return { proceed: true, safe: false }
    setSafe(req.target !== 'permanent')
    setState({ risk, target: req.target })
    return new Promise<RiskDecision>((resolve) => {
      resolver.current = resolve
    })
  }, [])

  function finish(d: RiskDecision) {
    resolver.current?.(d)
    resolver.current = null
    setState(null)
  }

  const danger = state?.risk.level === 'danger'
  const canSafe = state?.target !== 'permanent'
  const forced = !!state?.risk.force_safe

  return (
    <Ctx.Provider value={check}>
      {children}
      <AlertDialog open={state !== null} onOpenChange={(o) => !o && finish({ proceed: false, safe: false })}>
        <AlertDialogContent className="sm:max-w-lg">
          <AlertDialogHeader>
            <AlertDialogTitle className="flex items-center gap-2">
              {danger ? (
                <ShieldAlertIcon className="size-5 text-destructive" />
              ) : (
                <AlertTriangleIcon className="size-5 text-amber-500" />
              )}
              {danger ? 'This change could lock you out' : 'Check this change'}
            </AlertDialogTitle>
            <AlertDialogDescription asChild>
              <div className="grid gap-2 text-sm">
                <ul className="grid gap-1.5">
                  {state?.risk.warnings.map((w, i) => (
                    <li key={i} className={w.level === 'danger' ? 'text-destructive' : ''}>
                      • {w.message}
                    </li>
                  ))}
                </ul>
                {!canSafe && danger && (
                  <p>This is a permanent-only change: it takes effect on the next reload. Config history can restore the previous state.</p>
                )}
              </div>
            </AlertDialogDescription>
          </AlertDialogHeader>
          {canSafe && (
            <div className="flex items-center gap-2 rounded-md border p-3 text-sm">
              <Checkbox id="risk-safe" checked={safe || forced} disabled={forced} onCheckedChange={(c) => setSafe(c === true)} />
              <Label htmlFor="risk-safe" className="font-normal">
                Use safe apply (auto-revert unless confirmed){forced ? ' — required for this change' : ''}
              </Label>
            </div>
          )}
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <AlertDialogAction
              variant={danger ? 'destructive' : 'default'}
              onClick={() => finish({ proceed: true, safe: canSafe && (safe || forced) })}
            >
              Apply anyway
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </Ctx.Provider>
  )
}

export function useRiskCheck() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useRiskCheck outside RiskProvider')
  return ctx
}
