import { useQueryClient } from '@tanstack/react-query'
import {
  ArchiveIcon,
  ArrowLeftRightIcon,
  ActivityIcon,
  GlobeIcon,
  ShieldBanIcon,
  ChevronDownIcon,
  CircleUserIcon,
  FileClockIcon,
  FileCode2Icon,
  FolderSyncIcon,
  HistoryIcon,
  LayoutDashboardIcon,
  ListIcon,
  LogOutIcon,
  MonitorIcon,
  MoonIcon,
  NetworkIcon,
  RadarIcon,
  RefreshCwIcon,
  SaveIcon,
  ScrollTextIcon,
  ServerIcon,
  SettingsIcon,
  ShieldIcon,
  SunIcon,
  WandSparklesIcon,
} from 'lucide-react'
import { useTheme } from 'next-themes'
import type { ReactNode } from 'react'
import { Link, NavLink, useLocation } from 'react-router'
import { api } from '@/api/client'
import { useFwMutation, useHosts, useStatus, useZones } from '@/api/hooks'
import type { Me, Target } from '@/api/types'
import { ConfirmButton } from '@/components/ConfirmButton'
import { PendingChangesBar } from '@/components/PendingChangesBar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Separator } from '@/components/ui/separator'
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuBadge,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarProvider,
  SidebarTrigger,
} from '@/components/ui/sidebar'
import { Switch } from '@/components/ui/switch'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import { TARGET_LABELS, useApplyMode } from '@/lib/apply-mode'
import { useHostSwitcher } from '@/lib/host'

function AppSidebar({ me }: { me: Me }) {
  const zones = useZones()
  const status = useStatus()
  const { pathname } = useLocation()
  const qc = useQueryClient()

  const groups = [
    {
      label: null,
      items: [
        { to: '/', label: 'Dashboard', icon: LayoutDashboardIcon },
        { to: '/policies', label: 'Policies', icon: ArrowLeftRightIcon },
        { to: '/services', label: 'Services', icon: ListIcon },
        { to: '/ipsets', label: 'IP Sets', icon: NetworkIcon },
        { to: '/templates', label: 'Templates', icon: WandSparklesIcon },
        { to: '/ddns', label: 'Dynamic DNS', icon: GlobeIcon },
      ],
    },
    {
      label: 'Monitor & protect',
      items: [
        { to: '/denied', label: 'Denied traffic', icon: ScrollTextIcon },
        { to: '/connections', label: 'Connections', icon: ActivityIcon },
        { to: '/tester', label: 'Traffic tester', icon: RadarIcon },
        { to: '/fail2ban', label: 'Fail2ban', icon: ShieldBanIcon },
      ],
    },
    {
      label: 'Manage',
      items: [
        { to: '/backups', label: 'Backups', icon: ArchiveIcon },
        { to: '/history', label: 'Config history', icon: FileClockIcon },
        { to: '/import-export', label: 'Import / export', icon: FolderSyncIcon },
        { to: '/direct', label: 'Direct rules', icon: FileCode2Icon },
        { to: '/audit', label: 'Audit log', icon: HistoryIcon },
        { to: '/hosts', label: 'Hosts', icon: ServerIcon },
        { to: '/settings', label: 'Settings', icon: SettingsIcon },
      ],
    },
  ]

  async function logout() {
    try {
      await api.post('/logout')
    } finally {
      qc.clear()
      qc.setQueryData(['me'], null)
    }
  }

  return (
    <Sidebar>
      <SidebarHeader>
        <HostSwitcher me={me} />
        <Link to="/" className="flex items-center gap-2 px-2 py-1.5">
          <div className="flex size-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <ShieldIcon className="size-4" />
          </div>
          <div className="grid leading-tight">
            <span className="font-semibold">richrule</span>
            <span className="text-xs text-muted-foreground">
              firewalld {status.data?.version ?? '…'} · {status.data?.state ?? ''}
            </span>
          </div>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        {groups.slice(0, 1).map((g, gi) => (
          <SidebarGroup key={gi}>
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((n) => (
                  <SidebarMenuItem key={n.to}>
                    <SidebarMenuButton asChild isActive={pathname === n.to || (n.to !== '/' && pathname.startsWith(n.to + '/'))}>
                      <NavLink to={n.to}>
                        <n.icon />
                        <span>{n.label}</span>
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
        <SidebarGroup>
          <SidebarGroupLabel>Zones</SidebarGroupLabel>
          <SidebarGroupContent>
            <SidebarMenu>
              {zones.data
                ?.slice()
                .sort((a, b) => Number(b.active) - Number(a.active) || a.name.localeCompare(b.name))
                .map((z) => (
                  <SidebarMenuItem key={z.name}>
                    <SidebarMenuButton asChild isActive={pathname === `/zones/${z.name}`}>
                      <NavLink to={`/zones/${encodeURIComponent(z.name)}`}>
                        <span
                          className={`size-2 shrink-0 rounded-full ${z.active ? 'bg-emerald-500' : 'bg-muted-foreground/30'}`}
                        />
                        <span className="truncate">{z.name}</span>
                      </NavLink>
                    </SidebarMenuButton>
                    {z.default && <SidebarMenuBadge>default</SidebarMenuBadge>}
                  </SidebarMenuItem>
                ))}
            </SidebarMenu>
          </SidebarGroupContent>
        </SidebarGroup>
        {groups.slice(1).map((g) => (
          <SidebarGroup key={g.label}>
            <SidebarGroupLabel>{g.label}</SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {g.items.map((n) => (
                  <SidebarMenuItem key={n.to}>
                    <SidebarMenuButton asChild isActive={pathname === n.to}>
                      <NavLink to={n.to}>
                        <n.icon />
                        <span>{n.label}</span>
                      </NavLink>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
      <SidebarFooter>
        <SidebarMenu>
          <SidebarMenuItem>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <SidebarMenuButton>
                  <CircleUserIcon />
                  <span className="truncate">{me.user}</span>
                  {me.role === 'viewer' && (
                    <Badge variant="secondary" className="ml-auto">
                      read-only
                    </Badge>
                  )}
                  {me.dev_mode && (
                    <Badge variant="destructive" className="ml-auto">
                      dev
                    </Badge>
                  )}
                </SidebarMenuButton>
              </DropdownMenuTrigger>
              <DropdownMenuContent side="top" align="start" className="w-56">
                <DropdownMenuItem onClick={logout}>
                  <LogOutIcon /> Sign out
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </SidebarMenuItem>
        </SidebarMenu>
      </SidebarFooter>
    </Sidebar>
  )
}

function HostSwitcher({ me }: { me: Me }) {
  const hosts = useHosts()
  const { host, switchTo } = useHostSwitcher()
  if (!hosts.data?.length && !host) return null
  const LOCAL = '__local__'
  return (
    <Select value={host ?? LOCAL} onValueChange={(v) => switchTo(v === LOCAL ? null : v)}>
      <SelectTrigger size="sm" className="w-full" aria-label="Managed host">
        <ServerIcon className="size-4" />
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        <SelectItem value={LOCAL}>This host ({me.hostname})</SelectItem>
        {hosts.data?.map((h) => (
          <SelectItem key={h.id} value={h.id}>
            {h.name}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

function ThemeToggle() {
  const { theme, setTheme } = useTheme()
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" size="icon-sm" aria-label="Theme">
          <SunIcon className="dark:hidden" />
          <MoonIcon className="hidden dark:block" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuRadioGroup value={theme} onValueChange={setTheme}>
          <DropdownMenuRadioItem value="light">
            <SunIcon /> Light
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="dark">
            <MoonIcon /> Dark
          </DropdownMenuRadioItem>
          <DropdownMenuRadioItem value="system">
            <MonitorIcon /> System
          </DropdownMenuRadioItem>
        </DropdownMenuRadioGroup>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function GlobalActions() {
  const reload = useFwMutation((complete: boolean) => api.post('/reload', { complete }), 'firewalld reloaded')
  const r2p = useFwMutation(() => api.post('/runtime-to-permanent'), 'Runtime configuration saved as permanent')
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm">
          <RefreshCwIcon /> Config <ChevronDownIcon />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-72">
        <DropdownMenuLabel>Runtime / permanent</DropdownMenuLabel>
        <ConfirmButton
          asMenuItem
          title="Reload firewalld?"
          description="Discards all runtime-only changes and loads the permanent configuration. Established connections are kept."
          onConfirm={() => reload.mutate(false)}
        >
          <RefreshCwIcon /> Reload (apply permanent)
        </ConfirmButton>
        <ConfirmButton
          asMenuItem
          title="Save runtime as permanent?"
          description="Overwrites the permanent configuration with everything currently active at runtime."
          onConfirm={() => r2p.mutate(undefined)}
        >
          <SaveIcon /> Runtime → Permanent
        </ConfirmButton>
        <DropdownMenuSeparator />
        <ConfirmButton
          asMenuItem
          destructive
          title="Complete reload?"
          description="Reloads firewalld and its kernel modules. This drops ALL connections, including this one, briefly."
          onConfirm={() => reload.mutate(true)}
        >
          <RefreshCwIcon /> Complete reload
        </ConfirmButton>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}

function ApplyModeControls() {
  const { target, setTarget, safe, setSafe } = useApplyMode()
  return (
    <div className="flex items-center gap-3">
      <Tooltip>
        <TooltipTrigger asChild>
          <div>
            <Select value={target} onValueChange={(v) => setTarget(v as Target)}>
              <SelectTrigger size="sm" className="w-48" aria-label="Apply changes to">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {(Object.keys(TARGET_LABELS) as Target[]).map((t) => (
                  <SelectItem key={t} value={t}>
                    {TARGET_LABELS[t]}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </TooltipTrigger>
        <TooltipContent>Where new changes are written</TooltipContent>
      </Tooltip>
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="flex items-center gap-2">
            <Switch id="safe" checked={safe} onCheckedChange={setSafe} disabled={target === 'permanent'} />
            <Label htmlFor="safe" className="text-sm whitespace-nowrap">
              Safe apply
            </Label>
          </div>
        </TooltipTrigger>
        <TooltipContent className="max-w-xs">
          Apply at runtime first and auto-revert unless you confirm within the timeout — protects against locking
          yourself out.
        </TooltipContent>
      </Tooltip>
    </div>
  )
}

export function AppShell({ me, children }: { me: Me; children: ReactNode }) {
  const status = useStatus()
  const hosts = useHosts()
  const { host } = useHostSwitcher()
  const remote = host ? hosts.data?.find((h) => h.id === host) : null
  const canEdit = me.role === 'admin'
  return (
    <SidebarProvider>
      <AppSidebar me={me} />
      <SidebarInset>
        <header className="sticky top-0 z-10 flex h-14 items-center gap-2 border-b bg-background/95 px-4 backdrop-blur">
          <SidebarTrigger className="-ml-1" />
          <Separator orientation="vertical" className="mr-2 h-4" />
          {status.data?.panic_mode && <Badge variant="destructive">PANIC MODE — all traffic dropped</Badge>}
          {remote && (
            <Badge variant="outline" className="border-sky-500/50 text-sky-700 dark:text-sky-400">
              <ServerIcon /> managing {remote.name}
            </Badge>
          )}
          <div className="ml-auto flex items-center gap-3">
            {canEdit ? (
              <>
                <ApplyModeControls />
                <GlobalActions />
              </>
            ) : (
              <Badge variant="secondary">read-only access</Badge>
            )}
            <ThemeToggle />
          </div>
        </header>
        {canEdit && <PendingChangesBar />}
        <main className="flex-1 p-4 md:p-6">
          {children}
        </main>
      </SidebarInset>
    </SidebarProvider>
  )
}
