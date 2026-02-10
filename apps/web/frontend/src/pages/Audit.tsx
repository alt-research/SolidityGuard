import { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router'
import type { ToolInfo } from '../lib/types.ts'
import { api } from '../services/api.ts'
import { useAuditStream } from '../hooks/useAuditStream.ts'
import ProgressPanel from '../components/ProgressPanel.tsx'
import SeverityChart from '../components/SeverityChart.tsx'
import FindingCard from '../components/FindingCard.tsx'
import { FileCode, CheckCircle2, Loader2, XCircle, MinusCircle, AlertTriangle } from 'lucide-react'

const TOOL_STATUS_ICON: Record<string, React.ReactNode> = {
  done: <CheckCircle2 className="w-3.5 h-3.5 text-accent" />,
  running: <Loader2 className="w-3.5 h-3.5 text-severity-medium animate-spin" />,
  error: <XCircle className="w-3.5 h-3.5 text-severity-critical" />,
  idle: <MinusCircle className="w-3.5 h-3.5 text-text-secondary/40" />,
  unavailable: <MinusCircle className="w-3.5 h-3.5 text-text-secondary/20" />,
}

export default function Audit() {
  const { id } = useParams()
  const stream = useAuditStream(id)
  const [tools, setTools] = useState<ToolInfo[]>([])

  useEffect(() => {
    api.getTools().then(setTools).catch(() => {})
  }, [])

  const currentPhase = stream.phase || 1
  const progress = stream.progress || 0
  const totalPhases = stream.totalPhases || 7

  return (
    <div className="p-6">
      <div className="flex items-center gap-3 mb-6">
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">Audit #{id}</h1>
        {stream.isComplete ? (
          <span className="px-2.5 py-1 rounded-lg bg-accent/15 text-accent text-[11px] font-semibold">
            Complete
          </span>
        ) : stream.error ? (
          <span className="px-2.5 py-1 rounded-lg bg-severity-critical/15 text-severity-critical text-[11px] font-semibold">
            Error
          </span>
        ) : (
          <span className="px-2.5 py-1 rounded-lg bg-severity-medium/15 text-severity-medium text-[11px] font-semibold">
            Running
          </span>
        )}
      </div>

      {stream.error && (
        <div className="mb-4 flex items-center gap-2 text-[13px] text-severity-critical bg-severity-critical/10 border border-severity-critical/20 rounded-xl px-4 py-3">
          <AlertTriangle className="w-4 h-4 flex-shrink-0" />
          {stream.error}
        </div>
      )}

      <div className="grid grid-cols-[220px_1fr] gap-6">
        {/* Left panel */}
        <div className="space-y-6">
          <div>
            <h3 className="text-[11px] font-semibold text-text-secondary uppercase tracking-wider mb-2">Files</h3>
            <div className="space-y-1">
              {stream.findings.length > 0 ? (
                [...new Set(stream.findings.map((f) => f.file))].map((file) => (
                  <div key={file} className="flex items-center gap-2 px-2 py-1.5 rounded-lg hover:bg-surface-hover/30 text-[13px] text-text-secondary">
                    <FileCode className="w-3.5 h-3.5 text-accent/60" />
                    <span className="truncate">{file.split('/').pop()}</span>
                  </div>
                ))
              ) : (
                <div className="text-[11px] text-text-secondary/50 px-2">Waiting for scan...</div>
              )}
            </div>
          </div>

          <div className="h-px bg-border" />

          <div>
            <h3 className="text-[11px] font-semibold text-text-secondary uppercase tracking-wider mb-2">Tools</h3>
            <div className="space-y-1.5">
              {tools.map((tool) => (
                <div key={tool.name} className="flex items-center gap-2 text-[13px]">
                  {TOOL_STATUS_ICON[tool.status]}
                  <span className={tool.status === 'unavailable' ? 'text-text-secondary/30' : 'text-text-secondary'}>
                    {tool.label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Main content */}
        <div className="space-y-6">
          <div className="glass rounded-xl p-5">
            <ProgressPanel
              currentPhase={currentPhase}
              progress={progress}
              totalPhases={totalPhases}
            />
          </div>

          <div className="glass rounded-xl p-5">
            <h3 className="text-[13px] font-semibold text-text-primary mb-3">Severity Distribution</h3>
            <SeverityChart counts={stream.findingsCounts} />
          </div>

          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-[13px] font-semibold text-text-primary">
                Live Findings ({stream.findings.length})
              </h3>
              {stream.findings.length > 0 && (
                <Link
                  to={`/audit/${id}/findings`}
                  className="text-[12px] text-accent hover:text-accent-hover transition-colors no-underline"
                >
                  View All Findings
                </Link>
              )}
            </div>
            <div className="space-y-2">
              {stream.findings.map((finding, i) => (
                <FindingCard key={`${finding.id}-${i}`} finding={finding} />
              ))}
              {stream.findings.length === 0 && !stream.error && (
                <div className="text-center py-8 text-text-secondary text-[13px]">
                  Waiting for findings...
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
