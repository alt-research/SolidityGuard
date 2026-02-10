import { useState } from 'react'
import type { Finding } from '../lib/types'
import CodeSnippet from './CodeSnippet'
import { ChevronDown, ChevronRight, FileCode, MapPin } from 'lucide-react'

interface FindingCardProps {
  finding: Finding
}

const SEVERITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-severity-critical/10 text-severity-critical',
  HIGH: 'bg-severity-high/10 text-severity-high',
  MEDIUM: 'bg-severity-medium/10 text-severity-medium',
  LOW: 'bg-severity-low/10 text-severity-low',
  INFO: 'bg-severity-info/10 text-severity-info',
}

const SEVERITY_DOT: Record<string, string> = {
  CRITICAL: 'bg-severity-critical',
  HIGH: 'bg-severity-high',
  MEDIUM: 'bg-severity-medium',
  LOW: 'bg-severity-low',
  INFO: 'bg-severity-info',
}

export default function FindingCard({ finding }: FindingCardProps) {
  const [expanded, setExpanded] = useState(false)
  const [showAttack, setShowAttack] = useState(false)
  const [showRemediation, setShowRemediation] = useState(false)

  return (
    <div className="glass rounded-xl overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-5 py-4 flex items-center gap-3 hover:bg-surface-hover/30 transition-all duration-200 cursor-pointer text-left"
      >
        <span className={`w-2 h-2 rounded-full shrink-0 ${SEVERITY_DOT[finding.severity]}`} />
        <span className={`px-2.5 py-1 rounded-lg text-[11px] font-semibold ${SEVERITY_STYLES[finding.severity]}`}>
          {finding.severity}
        </span>
        <span className="text-[11px] font-mono text-text-secondary">{finding.id}</span>
        <span className="text-[13px] text-text-primary font-medium flex-1">{finding.title}</span>
        <div className="flex items-center gap-3 text-[11px] text-text-secondary">
          <span className="flex items-center gap-1">
            <FileCode className="w-3 h-3" />
            {finding.file}:{finding.line}
          </span>
          <span className={`font-semibold ${finding.confidence >= 0.9 ? 'text-accent' : finding.confidence >= 0.8 ? 'text-severity-medium' : 'text-text-secondary'}`}>
            {Math.round(finding.confidence * 100)}%
          </span>
        </div>
        {expanded ? <ChevronDown className="w-4 h-4 text-text-secondary shrink-0" /> : <ChevronRight className="w-4 h-4 text-text-secondary shrink-0" />}
      </button>

      {expanded && (
        <div className="px-5 pb-5 space-y-4 border-t border-border">
          <p className="text-[13px] text-text-secondary leading-relaxed pt-4">{finding.description}</p>

          {finding.swc && (
            <div className="flex items-center gap-2">
              <MapPin className="w-3 h-3 text-text-secondary" />
              <span className="text-[11px] text-text-secondary">
                {finding.swc} | {finding.category}
              </span>
            </div>
          )}

          <div>
            <h4 className="text-[11px] font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Vulnerable Code
            </h4>
            <CodeSnippet code={finding.code_snippet} startLine={Math.max(1, finding.line - 2)} />
          </div>

          {finding.attack_scenario && (
            <div>
              <button
                onClick={() => setShowAttack(!showAttack)}
                className="flex items-center gap-1.5 text-[13px] text-text-primary hover:text-accent transition-colors cursor-pointer font-medium"
              >
                {showAttack ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                Attack Scenario
              </button>
              {showAttack && (
                <div className="mt-2 pl-5 text-[13px] text-text-secondary whitespace-pre-line leading-relaxed">
                  {finding.attack_scenario}
                </div>
              )}
            </div>
          )}

          <div>
            <button
              onClick={() => setShowRemediation(!showRemediation)}
              className="flex items-center gap-1.5 text-[13px] text-text-primary hover:text-accent transition-colors cursor-pointer font-medium"
            >
              {showRemediation ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
              Remediation
            </button>
            {showRemediation && (
              <div className="mt-2">
                <CodeSnippet code={finding.remediation} startLine={finding.line} />
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
