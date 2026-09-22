import { useQueryClient } from '@tanstack/react-query'
import { createContext, useContext, useState, type ReactNode } from 'react'
import { setHost } from '@/api/client'

interface HostCtx {
  host: string | null
  switchTo: (id: string | null) => void
}

const Ctx = createContext<HostCtx | null>(null)

function initial(): string | null {
  try {
    const v = localStorage.getItem('richrule.host')
    setHost(v)
    return v
  } catch {
    return null
  }
}

/** Which host the UI is managing (null = this one). Switching resets all cached data. */
export function HostProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [host, setHostState] = useState<string | null>(initial)
  function switchTo(id: string | null) {
    setHost(id)
    setHostState(id)
    try {
      if (id) localStorage.setItem('richrule.host', id)
      else localStorage.removeItem('richrule.host')
    } catch {
      /* storage unavailable */
    }
    qc.resetQueries({ predicate: (q) => !['me', 'hosts'].includes(q.queryKey[0] as string) })
  }
  return <Ctx.Provider value={{ host, switchTo }}>{children}</Ctx.Provider>
}

export function useHostSwitcher() {
  const c = useContext(Ctx)
  if (!c) throw new Error('useHostSwitcher outside HostProvider')
  return c
}
