import { useState, useMemo, useEffect } from 'react'
import { useParams, Link } from 'react-router'
import type { Severity, Finding } from '../lib/types.ts'
import { SEVERITY_ORDER } from '../lib/types.ts'
import { api } from '../services/api.ts'
import ScoreBanner from '../components/ScoreBanner.tsx'
import FilterBar from '../components/FilterBar.tsx'
import FindingCard from '../components/FindingCard.tsx'
import { FileText, Loader2, Download } from 'lucide-react'

export default function Findings() {
  const { id } = useParams()
  const [selectedSeverities, setSelectedSeverities] = useState<Severity[]>([...SEVERITY_ORDER])
  const [selectedCategory, setSelectedCategory] = useState('')
  const [minConfidence, setMinConfidence] = useState(0)
  const [findings, setFindings] = useState<Finding[]>([])
  const [score, setScore] = useState<number>(0)
  const [filesCount, setFilesCount] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    setError(null)

    Promise.all([
      api.getFindings(id),
      api.getAuditStatus(id),
    ])
      .then(([findingsData, status]) => {
        setFindings(findingsData)
        const files = new Set(findingsData.map((f) => f.file))
        setFilesCount(files.size)
        // Derive score from status or report
        if (status.status === 'complete') {
          api.getReport(id).then((report) => {
            setScore(report.score)
          }).catch(() => {})
        }
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load findings')
      })
      .finally(() => setLoading(false))
  }, [id])

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      if (!selectedSeverities.includes(f.severity)) return false
      if (selectedCategory && f.category !== selectedCategory) return false
      if (f.confidence < minConfidence) return false
      return true
    })
  }, [findings, selectedSeverities, selectedCategory, minConfidence])

  const findingsCount = useMemo(() => {
    const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
    findings.forEach((f) => { counts[f.severity]++ })
    return counts
  }, [findings])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-text-secondary gap-2">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading findings...
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-6">
        <div className="text-[13px] text-severity-critical bg-severity-critical/10 border border-severity-critical/20 rounded-xl px-4 py-3">
          {error}
        </div>
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">Findings</h1>
        <Link
          to={`/audit/${id}/report`}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface border border-border text-sm text-text-secondary hover:text-text-primary hover:border-text-secondary/30 transition-colors no-underline"
        >
          <FileText className="w-4 h-4" />
          View Report
        </Link>
      </div>

      <div className="space-y-4">
        <ScoreBanner
          score={score}
          findingsCount={findingsCount}
          filesCount={filesCount}
        />

        <div className="flex items-center gap-2 text-[13px] text-accent bg-accent/10 border border-accent/20 rounded-xl px-4 py-3">
          <Download className="w-4 h-4 flex-shrink-0" />
          <span>
            Web scans use pattern matching and Slither. For deeper analysis with Mythril, Echidna, Foundry, and formal verification,{' '}
            <a href="https://github.com/alt-research/SolidityGuard/releases" target="_blank" rel="noopener noreferrer" className="underline hover:text-text-primary">
              download the desktop app
            </a>
            {' '}or install the{' '}
            <a href="https://github.com/alt-research/SolidityGuard#cli" target="_blank" rel="noopener noreferrer" className="underline hover:text-text-primary">
              CLI
            </a>.
          </span>
        </div>

        <FilterBar
          selectedSeverities={selectedSeverities}
          onSeveritiesChange={setSelectedSeverities}
          selectedCategory={selectedCategory}
          onCategoryChange={setSelectedCategory}
          minConfidence={minConfidence}
          onConfidenceChange={setMinConfidence}
        />

        <div className="flex items-center justify-between text-sm">
          <span className="text-text-secondary">
            Showing {filteredFindings.length} of {findings.length} findings
          </span>
        </div>

        <div className="space-y-2">
          {filteredFindings.map((finding, i) => (
            <FindingCard key={`${finding.id}-${i}`} finding={finding} />
          ))}
          {filteredFindings.length === 0 && (
            <div className="text-center py-12 text-text-secondary text-sm">
              No findings match the current filters
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
