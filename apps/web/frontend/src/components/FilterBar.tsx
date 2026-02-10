import type { Severity } from '../lib/types'
import { SEVERITY_ORDER, CATEGORIES } from '../lib/types'

interface FilterBarProps {
  selectedSeverities: Severity[]
  onSeveritiesChange: (severities: Severity[]) => void
  selectedCategory: string
  onCategoryChange: (category: string) => void
  minConfidence: number
  onConfidenceChange: (confidence: number) => void
}

const SEVERITY_COLORS: Record<Severity, string> = {
  CRITICAL: 'border-severity-critical bg-severity-critical/15 text-severity-critical',
  HIGH: 'border-severity-high bg-severity-high/15 text-severity-high',
  MEDIUM: 'border-severity-medium bg-severity-medium/15 text-severity-medium',
  LOW: 'border-severity-low bg-severity-low/15 text-severity-low',
  INFO: 'border-severity-info bg-severity-info/15 text-severity-info',
}

const SEVERITY_INACTIVE = 'border-border bg-surface text-text-secondary'

export default function FilterBar({
  selectedSeverities,
  onSeveritiesChange,
  selectedCategory,
  onCategoryChange,
  minConfidence,
  onConfidenceChange,
}: FilterBarProps) {
  const toggleSeverity = (severity: Severity) => {
    if (selectedSeverities.includes(severity)) {
      onSeveritiesChange(selectedSeverities.filter((s) => s !== severity))
    } else {
      onSeveritiesChange([...selectedSeverities, severity])
    }
  }

  const selectAll = () => onSeveritiesChange([...SEVERITY_ORDER])

  return (
    <div className="bg-surface rounded-lg border border-border p-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-text-secondary font-medium uppercase tracking-wider">Filters</span>
        <button
          onClick={selectAll}
          className="text-xs text-accent hover:text-accent-hover transition-colors cursor-pointer"
        >
          Select All
        </button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-text-secondary">Severity:</span>
        {SEVERITY_ORDER.map((severity) => (
          <button
            key={severity}
            onClick={() => toggleSeverity(severity)}
            className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors cursor-pointer ${
              selectedSeverities.includes(severity)
                ? SEVERITY_COLORS[severity]
                : SEVERITY_INACTIVE
            }`}
          >
            {severity}
          </button>
        ))}
      </div>

      <div className="flex items-center gap-4">
        <div className="flex items-center gap-2">
          <span className="text-xs text-text-secondary">Category:</span>
          <select
            value={selectedCategory}
            onChange={(e) => onCategoryChange(e.target.value)}
            className="bg-bg-tertiary border border-border rounded px-2 py-1 text-xs text-text-primary cursor-pointer"
          >
            <option value="">All Categories</option>
            {CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>{cat}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <span className="text-xs text-text-secondary">Confidence:</span>
          <select
            value={minConfidence}
            onChange={(e) => onConfidenceChange(Number(e.target.value))}
            className="bg-bg-tertiary border border-border rounded px-2 py-1 text-xs text-text-primary cursor-pointer"
          >
            <option value={0}>Any</option>
            <option value={0.7}>&ge; 70%</option>
            <option value={0.8}>&ge; 80%</option>
            <option value={0.9}>&ge; 90%</option>
          </select>
        </div>
      </div>
    </div>
  )
}
