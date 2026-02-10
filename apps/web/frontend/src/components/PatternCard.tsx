import type { VulnPattern } from '../lib/types'

interface PatternCardProps {
  pattern: VulnPattern
}

const SEVERITY_BADGE: Record<string, string> = {
  CRITICAL: 'bg-severity-critical/10 text-severity-critical',
  HIGH: 'bg-severity-high/10 text-severity-high',
  MEDIUM: 'bg-severity-medium/10 text-severity-medium',
  LOW: 'bg-severity-low/10 text-severity-low',
  INFO: 'bg-severity-info/10 text-severity-info',
}

export default function PatternCard({ pattern }: PatternCardProps) {
  return (
    <div className="glass rounded-xl p-5 hover:bg-surface-hover/30 transition-all duration-200 group">
      <div className="flex items-start justify-between gap-2 mb-3">
        <span className="font-mono text-[11px] text-text-secondary">{pattern.id}</span>
        <span className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold ${SEVERITY_BADGE[pattern.severity]}`}>
          {pattern.severity}
        </span>
      </div>
      <h3 className="text-[14px] font-semibold text-text-primary mb-1.5 group-hover:text-accent transition-colors">{pattern.name}</h3>
      <p className="text-[12px] text-text-secondary line-clamp-2 mb-3 leading-relaxed">{pattern.description}</p>
      <div className="flex items-center gap-2 text-[11px]">
        <span className="px-2 py-0.5 bg-surface/50 rounded-md text-text-secondary">{pattern.category}</span>
        {pattern.swc && (
          <span className="text-text-secondary/50">{pattern.swc}</span>
        )}
      </div>
    </div>
  )
}
