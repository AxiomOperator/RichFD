import { useApplyOps } from '@/api/hooks'
import type { Op, OpKind, Scope, Target } from '@/api/types'
import { useApplyMode } from '@/lib/apply-mode'
import { useRiskCheck } from '@/lib/risk'

export interface Presence {
  runtime: boolean
  permanent: boolean
}

export interface Merged<T> extends Presence {
  key: string
  item: T
}

/** Union of runtime and permanent items, flagged with where each one exists. */
export function mergeItems<T>(runtime: T[] | undefined, permanent: T[] | undefined, keyOf: (t: T) => string): Merged<T>[] {
  const map = new Map<string, Merged<T>>()
  for (const item of runtime ?? []) map.set(keyOf(item), { key: keyOf(item), item, runtime: true, permanent: false })
  for (const item of permanent ?? []) {
    const k = keyOf(item)
    const existing = map.get(k)
    if (existing) existing.permanent = true
    else map.set(k, { key: k, item, runtime: false, permanent: true })
  }
  return [...map.values()]
}

/** Narrow the user's chosen target to the configs where an existing item actually lives. */
export function removalTarget(where: Presence, chosen: Target): Target | null {
  const rt = where.runtime && chosen !== 'permanent'
  const pm = where.permanent && chosen !== 'runtime'
  if (rt && pm) return 'both'
  if (rt) return 'runtime'
  if (pm) return 'permanent'
  return null
}

/** Change helpers for one zone or policy, honoring the global apply mode and lock-out checks. */
export function useRuleOps(scope: Scope, name: string) {
  const { target, safe } = useApplyMode()
  const mutation = useApplyOps()
  const checkRisk = useRiskCheck()

  async function run(ops: Op[], where: Target = target, opts: { timeout?: number } = {}) {
    const decision = await checkRisk({ ops, target: where })
    if (!decision.proceed) throw new Error('cancelled')
    const useSafe = (safe || decision.safe) && where !== 'permanent' && !opts.timeout
    return mutation.mutateAsync({ ops, target: where, timeout: opts.timeout, safe: useSafe })
  }

  const op = (action: Op['action'], kind: OpKind, value: Record<string, string> = {}, on: string = name, sc: Scope = scope): Op => ({
    action,
    kind,
    zone: on,
    value,
    scope: sc,
  })

  return {
    scope,
    name,
    target,
    pending: mutation.isPending,
    run,
    add: (kind: OpKind, value: Record<string, string> = {}, opts: { timeout?: number; where?: Target } = {}) =>
      run([op('add', kind, value)], opts.where ?? (opts.timeout ? 'runtime' : target), opts),
    remove: (kind: OpKind, value: Record<string, string>, where: Presence) => {
      const t = removalTarget(where, target)
      if (!t) return Promise.reject(new Error(`Not present in ${target} configuration`))
      return run([op('remove', kind, value)], t)
    },
    /** Copy an item into the config where it is missing. */
    sync: (kind: OpKind, value: Record<string, string>, where: Presence) =>
      run([op('add', kind, value)], where.runtime ? 'permanent' : 'runtime'),
    op,
  }
}

export type RuleOps = ReturnType<typeof useRuleOps>
