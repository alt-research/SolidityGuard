import type { Severity } from '../lib/types'

interface StatusBarProps {
  counts?: Record<Severity, number>
  status?: string
  total?: number
}

const SEVERITY_SYMBOLS: { key: Severity; symbol: string; color: string }[] = [
  { key: 'CRITICAL', symbol: '\u25CF', color: 'text-severity-critical' },
  { key: 'HIGH', symbol: '\u25C6', color: 'text-severity-high' },
  { key: 'MEDIUM', symbol: '\u25B2', color: 'text-severity-medium' },
  { key: 'LOW', symbol: '\u25A0', color: 'text-severity-low' },
]

export default function StatusBar({ counts, status, total }: StatusBarProps) {
  const totalFindings = total ?? (counts
    ? Object.values(counts).reduce((a, b) => a + b, 0)
    : 0)

  return (
    <footer className="h-8 shrink-0 border-t border-border bg-bg-secondary/40 flex items-center justify-between px-4 text-[11px]">
      <div className="flex items-center gap-4">
        {status && (
          <span className="flex items-center gap-1.5">
            <span
              className={`w-1.5 h-1.5 rounded-full ${
                status === 'complete'
                  ? 'bg-severity-low'
                  : status === 'running'
                  ? 'bg-accent animate-pulse'
                  : status === 'failed'
                  ? 'bg-severity-critical'
                  : 'bg-text-secondary'
              }`}
            />
            <span className="text-text-secondary capitalize">{status}</span>
          </span>
        )}
        {counts && (
          <div className="flex items-center gap-3">
            {SEVERITY_SYMBOLS.map(({ key, symbol, color }) => (
              <span key={key} className="flex items-center gap-1">
                <span className={color}>{symbol}</span>
                <span className="text-text-secondary">{counts[key] || 0}</span>
              </span>
            ))}
          </div>
        )}
      </div>

      <div className="flex items-center gap-4 text-text-secondary">
        <span>{totalFindings} findings</span>
        <span>SolidityGuard v1.0</span>
      </div>
    </footer>
  )
}
