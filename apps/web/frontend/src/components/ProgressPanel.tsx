import { AUDIT_PHASES } from '../lib/types'
import { CheckCircle2, Loader2, Circle } from 'lucide-react'

interface ProgressPanelProps {
  currentPhase: number
  progress: number
  totalPhases: number
}

export default function ProgressPanel({ currentPhase, progress, totalPhases }: ProgressPanelProps) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-text-primary">
          Phase {currentPhase} of {totalPhases}: {AUDIT_PHASES[currentPhase - 1] || 'Unknown'}
        </h3>
        <span className="text-xs text-text-secondary">{Math.round(progress * 100)}%</span>
      </div>

      <div className="w-full bg-bg-tertiary rounded-full h-2">
        <div
          className="bg-accent h-2 rounded-full transition-all duration-500"
          style={{ width: `${progress * 100}%` }}
        />
      </div>

      <div className="space-y-2 mt-4">
        {AUDIT_PHASES.map((phase, i) => {
          const phaseNum = i + 1
          const isComplete = phaseNum < currentPhase
          const isCurrent = phaseNum === currentPhase
          const isPending = phaseNum > currentPhase

          return (
            <div key={phase} className="flex items-center gap-3">
              {isComplete && <CheckCircle2 className="w-4 h-4 text-accent flex-shrink-0" />}
              {isCurrent && <Loader2 className="w-4 h-4 text-accent animate-spin flex-shrink-0" />}
              {isPending && <Circle className="w-4 h-4 text-text-secondary/40 flex-shrink-0" />}
              <span
                className={`text-sm ${
                  isComplete ? 'text-text-secondary' : isCurrent ? 'text-text-primary font-medium' : 'text-text-secondary/40'
                }`}
              >
                {phaseNum}. {phase}
              </span>
              {isCurrent && (
                <span className="text-xs text-accent ml-auto">{Math.round(progress * 100)}%</span>
              )}
              {isComplete && (
                <span className="text-xs text-text-secondary ml-auto">Done</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}
