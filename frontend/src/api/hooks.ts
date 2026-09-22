import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { toast } from 'sonner'
import { api } from './client'
import type {
  AuditEntry,
  DirectRules,
  Host,
  HistoryLog,
  IPSet,
  NotificationSettings,
  Op,
  PendingChange,
  PolicyDetail,
  PolicySummary,
  RichRule,
  Service,
  Status,
  Target,
  Template,
  ZoneDetail,
  ZoneSummary,
} from './types'

export const useStatus = () => useQuery({ queryKey: ['status'], queryFn: () => api.get<Status>('/status') })

export const useZones = () => useQuery({ queryKey: ['zones'], queryFn: () => api.get<ZoneSummary[]>('/zones') })

export const useZone = (name: string) =>
  useQuery({ queryKey: ['zone', name], queryFn: () => api.get<ZoneDetail>(`/zones/${encodeURIComponent(name)}`) })

export const usePolicies = () =>
  useQuery({ queryKey: ['policies'], queryFn: () => api.get<PolicySummary[]>('/policies') })

export const usePolicy = (name: string) =>
  useQuery({
    queryKey: ['policy', name],
    queryFn: () => api.get<PolicyDetail>(`/policies/${encodeURIComponent(name)}`),
  })

export const useServices = () =>
  useQuery({ queryKey: ['services'], queryFn: () => api.get<Service[]>('/services'), staleTime: 60_000 })

export const useHelpers = () =>
  useQuery({ queryKey: ['helpers'], queryFn: () => api.get<string[]>('/helpers'), staleTime: 5 * 60_000 })

export const useIcmpTypes = () =>
  useQuery({ queryKey: ['icmptypes'], queryFn: () => api.get<string[]>('/icmptypes'), staleTime: 5 * 60_000 })

export const useIPSets = () =>
  useQuery({ queryKey: ['ipsets'], queryFn: () => api.get<{ runtime: IPSet[]; permanent: IPSet[] }>('/ipsets') })

export const useAudit = () =>
  useQuery({ queryKey: ['audit'], queryFn: () => api.get<AuditEntry[]>('/audit?limit=500') })

export const useHistory = () =>
  useQuery({ queryKey: ['history'], queryFn: () => api.get<HistoryLog>('/history?limit=300') })

export const useTemplates = () =>
  useQuery({ queryKey: ['templates'], queryFn: () => api.get<Template[]>('/templates'), staleTime: Infinity })

export const useDirect = () =>
  useQuery({
    queryKey: ['direct'],
    queryFn: () => api.get<{ runtime: DirectRules; permanent: DirectRules }>('/direct'),
  })

export const useHosts = () => useQuery({ queryKey: ['hosts'], queryFn: () => api.get<Host[]>('/hosts') })

export const useTokens = () =>
  useQuery({
    queryKey: ['tokens'],
    queryFn: () => api.get<{ name: string; created: string; last_used: string }[]>('/tokens'),
  })

export const useNotificationSettings = () =>
  useQuery({ queryKey: ['notifications'], queryFn: () => api.get<NotificationSettings>('/settings/notifications') })

export const usePending = () =>
  useQuery({
    queryKey: ['safe-apply'],
    queryFn: () => api.get<PendingChange | null>('/safe-apply'),
    refetchInterval: (q) => (q.state.data ? 1000 : false),
  })

const STATIC_KEYS = new Set(['icmptypes', 'helpers', 'templates', 'me', 'hosts'])

/** Generic mutation that refreshes firewall state and reports errors as toasts. */
export function useFwMutation<V, R = unknown>(
  fn: (vars: V) => Promise<R>,
  success?: string | ((vars: V, result: R) => string),
) {
  const qc = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: (result, vars) => {
      if (success) toast.success(typeof success === 'function' ? success(vars, result) : success)
    },
    onError: (e: Error) => toast.error(e.message),
    onSettled: () => {
      qc.invalidateQueries({ predicate: (q) => !STATIC_KEYS.has(q.queryKey[0] as string) })
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
    ({ safe, ops }) =>
      safe ? 'Applied at runtime — confirm to keep it' : ops.length > 1 ? `${ops.length} changes applied` : 'Change applied',
  )
}

export const renderRule = (rule: RichRule) =>
  api.post<{ valid: boolean; rule?: string; error?: string }>('/rich-rules/render', rule)

export const parseRule = (rule: string) =>
  api.post<{ valid: boolean; rule?: string; parsed?: RichRule; error?: string }>('/rich-rules/parse', { rule })
