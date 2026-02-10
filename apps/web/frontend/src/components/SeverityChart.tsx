import type { Severity } from '../lib/types'
import { SEVERITY_ORDER } from '../lib/types'

interface SeverityChartProps {
  counts: Record<Severity, number>
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: '#ff4757',
  HIGH: '#ff6b35',
  MEDIUM: '#ffc048',
  LOW: '#4da6ff',
  INFO: '#6c6c80',
}

export default function SeverityChart({ counts }: SeverityChartProps) {
  const total = SEVERITY_ORDER.reduce((sum, s) => sum + (counts[s] || 0), 0)

  if (total === 0) {
    return (
      <div className="flex items-center justify-center h-40 text-text-secondary text-sm">
        No findings yet
      </div>
    )
  }

  // Build SVG donut chart
  const size = 120
  const strokeWidth = 20
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  let offset = 0

  const segments = SEVERITY_ORDER
    .filter((s) => counts[s] > 0)
    .map((severity) => {
      const count = counts[severity]
      const fraction = count / total
      const dashLength = fraction * circumference
      const segment = {
        severity,
        count,
        dashArray: `${dashLength} ${circumference - dashLength}`,
        dashOffset: -offset,
        color: SEVERITY_COLORS[severity],
      }
      offset += dashLength
      return segment
    })

  return (
    <div className="flex items-center gap-6">
      <div className="relative flex-shrink-0">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
          {segments.map((seg) => (
            <circle
              key={seg.severity}
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke={seg.color}
              strokeWidth={strokeWidth}
              strokeDasharray={seg.dashArray}
              strokeDashoffset={seg.dashOffset}
              transform={`rotate(-90 ${size / 2} ${size / 2})`}
            />
          ))}
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-xl font-bold text-text-primary">{total}</span>
        </div>
      </div>

      <div className="space-y-1.5">
        {SEVERITY_ORDER.map((severity) => {
          const count = counts[severity] || 0
          if (count === 0) return null
          return (
            <div key={severity} className="flex items-center gap-2 text-sm">
              <div
                className="w-3 h-3 rounded-sm flex-shrink-0"
                style={{ backgroundColor: SEVERITY_COLORS[severity] }}
              />
              <span className="text-text-secondary w-16">{severity}</span>
              <span className="text-text-primary font-medium">{count}</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
