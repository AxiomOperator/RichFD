import { ArrowRightLeftIcon } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip'
import type { Presence } from '@/lib/zone-ops'

/** Shows when an item exists only in runtime or only in permanent config, with a sync action. */
export function PresenceBadge({ where, onSync }: { where: Presence; onSync?: () => void }) {
  if (where.runtime && where.permanent) return null
  const label = where.runtime ? 'runtime only' : 'permanent only'
  const hint = where.runtime
    ? 'Active now but will be lost on reload. Click to save it to permanent config.'
    : 'Saved but not active yet. Click to activate it at runtime.'
  return (
    <span className="inline-flex items-center gap-1">
      <Badge variant={where.runtime ? 'secondary' : 'outline'} className={where.runtime ? 'text-amber-700 dark:text-amber-400' : ''}>
        {label}
      </Badge>
      {onSync && (
        <Tooltip>
          <TooltipTrigger asChild>
            <Button variant="ghost" size="icon-xs" onClick={onSync} aria-label="Sync">
              <ArrowRightLeftIcon />
            </Button>
          </TooltipTrigger>
          <TooltipContent className="max-w-xs">{hint}</TooltipContent>
        </Tooltip>
      )}
    </span>
  )
}
