import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { Navigate, Route, Routes } from 'react-router'
import { api, ApiError, setCsrf } from '@/api/client'
import type { Me } from '@/api/types'
import { AppShell } from '@/components/AppShell'
import { ApplyModeProvider } from '@/lib/apply-mode'
import { HostProvider } from '@/lib/host'
import { RiskProvider } from '@/lib/risk'
import { SessionContext } from '@/lib/session'
import AuditPage from '@/pages/Audit'
import BackupsPage from '@/pages/Backups'
import ConnectionsPage from '@/pages/Connections'
import DdnsPage from '@/pages/Ddns'
import Fail2banPage from '@/pages/Fail2ban'
import Dashboard from '@/pages/Dashboard'
import DeniedPage from '@/pages/Denied'
import DirectPage from '@/pages/Direct'
import HistoryPage from '@/pages/History'
import HostsPage from '@/pages/Hosts'
import ImportExportPage from '@/pages/ImportExport'
import IPSetsPage from '@/pages/IPSets'
import LoginPage from '@/pages/Login'
import PoliciesPage from '@/pages/Policies'
import PolicyPage from '@/pages/Policy'
import ServicesPage from '@/pages/Services'
import SettingsPage from '@/pages/Settings'
import TemplatesPage from '@/pages/Templates'
import TesterPage from '@/pages/Tester'
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
    <SessionContext.Provider value={me.data}>
      <HostProvider>
        <ApplyModeProvider>
          <RiskProvider>
            <AppShell me={me.data}>
              <Routes>
                <Route path="/" element={<Dashboard />} />
                <Route path="/zones/:name" element={<ZonePage />} />
                <Route path="/policies" element={<PoliciesPage />} />
                <Route path="/policies/:name" element={<PolicyPage />} />
                <Route path="/services" element={<ServicesPage />} />
                <Route path="/ipsets" element={<IPSetsPage />} />
                <Route path="/tester" element={<TesterPage />} />
                <Route path="/denied" element={<DeniedPage />} />
                <Route path="/connections" element={<ConnectionsPage />} />
                <Route path="/fail2ban" element={<Fail2banPage />} />
                <Route path="/ddns" element={<DdnsPage />} />
                <Route path="/backups" element={<BackupsPage />} />
                <Route path="/templates" element={<TemplatesPage />} />
                <Route path="/history" element={<HistoryPage />} />
                <Route path="/import-export" element={<ImportExportPage />} />
                <Route path="/direct" element={<DirectPage />} />
                <Route path="/audit" element={<AuditPage />} />
                <Route path="/hosts" element={<HostsPage />} />
                <Route path="/settings" element={<SettingsPage />} />
                <Route path="*" element={<Navigate to="/" replace />} />
              </Routes>
            </AppShell>
          </RiskProvider>
        </ApplyModeProvider>
      </HostProvider>
    </SessionContext.Provider>
  )
}
