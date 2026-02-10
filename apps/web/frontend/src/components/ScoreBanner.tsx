import type { Severity } from '../lib/types'

interface ScoreBannerProps {
  score: number
  findingsCount: Record<Severity, number>
  filesCount: number
}

function getScoreColor(score: number): string {
  if (score >= 80) return 'text-accent'
  if (score >= 60) return 'text-severity-medium'
  if (score >= 40) return 'text-severity-high'
  return 'text-severity-critical'
}

function getScoreLabel(score: number): string {
  if (score >= 90) return 'Excellent'
  if (score >= 80) return 'Good'
  if (score >= 60) return 'Fair'
  if (score >= 40) return 'Poor'
  return 'Critical'
}

export default function ScoreBanner({ score, findingsCount, filesCount }: ScoreBannerProps) {
  const totalFindings = Object.values(findingsCount).reduce((a, b) => a + b, 0)

  return (
    <div className="bg-surface rounded-lg border border-border p-6">
      <div className="flex items-center gap-8">
        <div className="text-center">
          <div className={`text-5xl font-bold ${getScoreColor(score)}`}>
            {score}
          </div>
          <div className="text-xs text-text-secondary mt-1">/ 100</div>
          <div className={`text-sm font-medium mt-1 ${getScoreColor(score)}`}>
            {getScoreLabel(score)}
          </div>
        </div>

        <div className="h-16 w-px bg-border" />

        <div className="flex items-center gap-6 text-sm">
          <div className="text-center">
            <div className="text-2xl font-bold text-text-primary">{totalFindings}</div>
            <div className="text-xs text-text-secondary">Findings</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-severity-critical">{findingsCount.CRITICAL || 0}</div>
            <div className="text-xs text-text-secondary">Critical</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-severity-high">{findingsCount.HIGH || 0}</div>
            <div className="text-xs text-text-secondary">High</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-severity-medium">{findingsCount.MEDIUM || 0}</div>
            <div className="text-xs text-text-secondary">Medium</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-text-primary">{filesCount}</div>
            <div className="text-xs text-text-secondary">Files</div>
          </div>
        </div>
      </div>
    </div>
  )
}
