import { createContext, useContext, useState, type ReactNode } from 'react'
import type { Target } from '@/api/types'

interface ApplyMode {
  target: Target
  setTarget: (t: Target) => void
  /** Apply at runtime with auto-revert unless confirmed (lockout protection). */
  safe: boolean
  setSafe: (s: boolean) => void
}

const Ctx = createContext<ApplyMode | null>(null)

function load<T>(key: string, fallback: T): T {
  try {
    const v = localStorage.getItem(key)
    return v === null ? fallback : (JSON.parse(v) as T)
  } catch {
    return fallback
  }
}

function save(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value))
  } catch {
    /* storage unavailable */
  }
}

export function ApplyModeProvider({ children }: { children: ReactNode }) {
  const [target, setTargetState] = useState<Target>(() => load('richrule.target', 'both'))
  const [safe, setSafeState] = useState<boolean>(() => load('richrule.safe', false))
  const setTarget = (t: Target) => {
    setTargetState(t)
    save('richrule.target', t)
  }
  const setSafe = (s: boolean) => {
    setSafeState(s)
    save('richrule.safe', s)
  }
  return <Ctx.Provider value={{ target, setTarget, safe, setSafe }}>{children}</Ctx.Provider>
}

export function useApplyMode() {
  const ctx = useContext(Ctx)
  if (!ctx) throw new Error('useApplyMode outside ApplyModeProvider')
  return ctx
}

export const TARGET_LABELS: Record<Target, string> = {
  both: 'Runtime + Permanent',
  runtime: 'Runtime only',
  permanent: 'Permanent only',
}
