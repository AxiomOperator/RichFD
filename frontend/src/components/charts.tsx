import { useState, type ReactNode } from 'react'

/**
 * Minimal single-series charts (dataviz method): one hue (--viz-series-1), thin marks with a
 * 4px rounded data end, recessive axes, a hover tooltip per mark, and values that are also
 * readable without hovering (direct labels / the table beside the chart).
 */

export interface TimePoint {
  t: string
  count: number
}

export function ColumnChart({ data, height = 160, label }: { data: TimePoint[]; height?: number; label: string }) {
  const [hover, setHover] = useState<number | null>(null)
  const max = Math.max(1, ...data.map((d) => d.count))
  const padL = 36
  const padB = 22
  const width = 800
  const plotW = width - padL - 8
  const plotH = height - padB - 8
  const band = plotW / Math.max(1, data.length)
  const barW = Math.max(1, Math.min(24, band - 2))
  const ticks = [0, Math.ceil(max / 2), max]
  const fmtTime = (t: string) => {
    const d = new Date(t)
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
  }
  const labelEvery = Math.max(1, Math.ceil(data.length / 8))
  const h = hover !== null ? data[hover] : null

  return (
    <div className="relative">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-auto w-full" role="img" aria-label={label}>
        {ticks.map((v) => {
          const y = 8 + plotH - (v / max) * plotH
          return (
            <g key={v}>
              <line x1={padL} x2={width - 8} y1={y} y2={y} className="stroke-border" strokeWidth={1} />
              <text x={padL - 6} y={y + 4} textAnchor="end" className="fill-muted-foreground text-[11px]">
                {v}
              </text>
            </g>
          )
        })}
        {data.map((d, i) => {
          const bh = (d.count / max) * plotH
          const x = padL + i * band + (band - barW) / 2
          const y = 8 + plotH - bh
          const r = Math.min(4, barW / 2, bh)
          return (
            <g key={d.t}>
              {bh > 0 && (
                <path
                  d={`M${x},${y + bh} V${y + r} Q${x},${y} ${x + r},${y} H${x + barW - r} Q${x + barW},${y} ${x + barW},${y + r} V${y + bh} Z`}
                  fill="var(--viz-series-1)"
                  opacity={hover === null || hover === i ? 1 : 0.55}
                />
              )}
              {/* hit target: the full band, taller than the mark */}
              <rect
                x={padL + i * band}
                y={8}
                width={band}
                height={plotH}
                fill="transparent"
                tabIndex={0}
                aria-label={`${fmtTime(d.t)}: ${d.count}`}
                onPointerEnter={() => setHover(i)}
                onPointerLeave={() => setHover(null)}
                onFocus={() => setHover(i)}
                onBlur={() => setHover(null)}
              />
              {i % labelEvery === 0 && (
                <text x={padL + i * band + band / 2} y={height - 6} textAnchor="middle" className="fill-muted-foreground text-[11px]">
                  {fmtTime(d.t)}
                </text>
              )}
            </g>
          )
        })}
        <line x1={padL} x2={width - 8} y1={8 + plotH} y2={8 + plotH} className="stroke-muted-foreground/40" strokeWidth={1} />
      </svg>
      {h && hover !== null && (
        <div
          className="pointer-events-none absolute top-0 rounded-md border bg-popover px-2 py-1 text-xs shadow-sm"
          style={{ left: `calc(${((padL + hover * band + band / 2) / width) * 100}% - 3rem)` }}
        >
          <div className="font-semibold tabular-nums">{h.count}</div>
          <div className="text-muted-foreground">{new Date(h.t).toLocaleString([], { dateStyle: 'short', timeStyle: 'short' })}</div>
        </div>
      )}
    </div>
  )
}

export interface BarItem {
  key: string
  label: ReactNode
  value: number
  detail?: ReactNode
  actions?: ReactNode
}

/** Horizontal bar list: label, bar, value always visible (it doubles as the table view). */
export function BarList({ items, empty = 'No data' }: { items: BarItem[]; empty?: string }) {
  const max = Math.max(1, ...items.map((i) => i.value))
  if (!items.length) return <p className="py-6 text-center text-sm text-muted-foreground">{empty}</p>
  return (
    <ul className="grid gap-1.5">
      {items.map((it) => (
        <li key={it.key} className="group grid grid-cols-[minmax(7rem,12rem)_1fr_auto] items-center gap-3 text-sm" title={`${it.key}: ${it.value}`}>
          <div className="min-w-0">
            <div className="truncate font-mono text-xs">{it.label}</div>
            {it.detail && <div className="truncate text-[11px] text-muted-foreground">{it.detail}</div>}
          </div>
          <div className="h-4">
            <div
              className="h-full rounded-r-[4px] transition-opacity group-hover:opacity-80"
              style={{ width: `${Math.max(2, (it.value / max) * 100)}%`, background: 'var(--viz-series-1)' }}
            />
          </div>
          <div className="flex items-center gap-1">
            <span className="w-12 text-right font-medium tabular-nums">{it.value.toLocaleString()}</span>
            {it.actions}
          </div>
        </li>
      ))}
    </ul>
  )
}

export function StatTile({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="rounded-xl border bg-card p-4">
      <div className="text-sm text-muted-foreground">{label}</div>
      <div className="mt-1 text-2xl font-semibold tabular-nums">{value}</div>
      {hint && <div className="mt-0.5 truncate text-xs text-muted-foreground">{hint}</div>}
    </div>
  )
}
