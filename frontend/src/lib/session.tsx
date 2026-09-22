import { createContext, useContext } from 'react'
import type { Me } from '@/api/types'

export const SessionContext = createContext<Me | null>(null)

export function useSession() {
  const me = useContext(SessionContext)
  if (!me) throw new Error('useSession outside SessionContext')
  return me
}

export const useCanEdit = () => useSession().role === 'admin'
