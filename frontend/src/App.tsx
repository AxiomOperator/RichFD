import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import { api, ApiError, setCsrf } from '@/api/client'
import type { Me } from '@/api/types'
import { AppShell } from '@/components/AppShell'
import { ApplyModeProvider } from '@/lib/apply-mode'
import AuditPage from '@/pages/Audit'
import Dashboard from '@/pages/Dashboard'
import IPSetsPage from '@/pages/IPSets'
import LoginPage from '@/pages/Login'
import ServicesPage from '@/pages/Services'
import ZonePage from '@/pages/Zone'

export default function App() {
  const qc = useQueryClient()
  const me = useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      try {
        const m = await api.get<Me>('/me')
        setCsrf(m.csrf)
        return m
      } catch (e) {
        if (e instanceof ApiError && e.status === 401) return null
        throw e
      }
    },
    staleTime: Infinity,
  })

  useEffect(() => {
    const onUnauthorized = () => qc.setQueryData(['me'], null)
    window.addEventListener('richrule:unauthorized', onUnauthorized)
    return () => window.removeEventListener('richrule:unauthorized', onUnauthorized)
  }, [qc])

  if (me.isPending) return null
  if (me.isError)
    return <div className="p-8 text-destructive">Cannot reach the richrule backend: {me.error.message}</div>
  if (!me.data) return <LoginPage />

  return (
    <ApplyModeProvider>
      <AppShell me={me.data}>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/zones/:name" element={<ZonePage />} />
          <Route path="/services" element={<ServicesPage />} />
          <Route path="/ipsets" element={<IPSetsPage />} />
          <Route path="/audit" element={<AuditPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </AppShell>
    </ApplyModeProvider>
  )
}
