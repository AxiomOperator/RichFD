/** Minimal unified-diff renderer with per-file sections. */
export function DiffView({ diff }: { diff: string }) {
  if (!diff.trim()) return <p className="text-sm text-muted-foreground">No differences.</p>
  const lines = diff.split('\n')
  return (
    <pre className="max-h-[60svh] overflow-auto rounded-md border bg-muted/30 text-xs leading-5">
      {lines.map((l, i) => {
        let cls = 'px-3'
        if (l.startsWith('diff --git')) cls = 'mt-2 border-t bg-muted px-3 py-1 font-semibold first:mt-0 first:border-t-0'
        else if (l.startsWith('+++') || l.startsWith('---') || l.startsWith('index ') || l.startsWith('new file') || l.startsWith('deleted file'))
          cls = 'px-3 text-muted-foreground'
        else if (l.startsWith('@@')) cls = 'px-3 text-sky-700 dark:text-sky-400'
        else if (l.startsWith('+')) cls = 'bg-emerald-500/15 px-3 text-emerald-800 dark:text-emerald-300'
        else if (l.startsWith('-')) cls = 'bg-red-500/15 px-3 text-red-800 dark:text-red-300'
        const text = l.startsWith('diff --git') ? l.replace(/^diff --git a\/tree\/(\S+) b\/tree\/.*$/, '$1') : l
        return (
          <div key={i} className={cls}>
            {text || ' '}
          </div>
        )
      })}
    </pre>
  )
}
