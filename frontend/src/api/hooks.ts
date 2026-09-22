import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { api } from './client'
import type {
  AuditEntry,
  IPSet,
  Op,
  PendingChange,
  RichRule,
  Service,
  Status,
  Target,
  ZoneDetail,
  ZoneSummary,
} from './types'

export const useStatus = () => useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/status') })

export const useZones = () => useQuery({ queryKey: ['zones'], queryFn: () => api.get<ZoneSummary[]>('/zones') })

export const useZone = (name: string) =>
  useQuery({ queryKey: ['zone', name], queryFn: () => api.get<ZoneDetail>(`/zones/${encodeURIComponent(name)}`) })

export const useServices = () =>
  useQuery({ queryKey: ['services'], queryFn: () => api.get<Service[]>('/services'), staleTime: 5 * 60_000 })

export const useIcmpTypes = () =>
  useQuery({ queryKey: ['icmptypes'], queryFn: () => api.get<string[]>('/icmptypes'), staleTime: 5 * 60_000 })

export const useIPSets = () =>
  useQuery({ queryKey: ['ipsets'], queryFn: () => api.get<{ runtime: IPSet[]; permanent: IPSet[] }>('/ipsets') })

export const useAudit = () =>
  useQuery({ queryKey: ['audit'], queryFn: () => api.get<AuditEntry[]>('/audit?limit=500') })

export const usePending = () =>
  useQuery({
    queryKey: ['safe-apply'],
    queryFn: () => api.get<PendingChange | null>('/safe-apply'),
    refetchInterval: (q) => (q.state.data ? 1000 : false),
  })

/** Generic mutation that refreshes all firewall state and reports errors as toasts. */
export function useFwMutation<V>(fn: (vars: V) => Promise<unknown>, success?: string | ((vars: V) => string)) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (_d, vars) => {
      if (success) toast.success(typeof success === 'function' ? success(vars) : success)
    },
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => {
      qc.invalidateQueries({ predicate: (q) => q.queryKey[0] !== 'services' && q.queryKey[0] !== 'icmptypes' })
    },
  })
}

export interface ApplyVars {
  ops: Op[]
  target: Target
  timeout?: number
  safe?: boolean
}

export function useApplyOps() {
  return useFwMutation(
    ({ ops, target, timeout, safe }: ApplyVars) =>
      safe
        ? api.post('/safe-apply', { ops, persist: target !== 'runtime' })
        : api.post('/ops', { ops, target, timeout: timeout ?? 0 }),
    ({ safe }) => (safe ? 'Applied at runtime — confirm to keep it' : 'Change applied'),
  )
}

export const renderRule = (rule: RichRule) =>
  api.post<{ valid: boolean; rule?: string; error?: string }>('/rich-rules/render', rule)

export const parseRule = (rule: string) =>
  api.post<{ valid: boolean; rule?: string; parsed?: RichRule; error?: string }>('/rich-rules/parse', { rule })
