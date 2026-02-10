import type { AuditMode, ToolName } from '../lib/types'
import { Zap, Layers, Brain } from 'lucide-react'

interface AuditConfigProps {
  mode: AuditMode
  onModeChange: (mode: AuditMode) => void
  tools: ToolName[]
  onToolsChange: (tools: ToolName[]) => void
}

const MODES: { value: AuditMode; label: string; desc: string; icon: React.ReactNode }[] = [
  { value: 'quick', label: 'Quick', desc: 'Pattern scanner', icon: <Zap className="w-4 h-4" /> },
  { value: 'standard', label: 'Standard', desc: 'Multi-tool scan', icon: <Layers className="w-4 h-4" /> },
  { value: 'deep', label: 'Deep', desc: 'Agent team', icon: <Brain className="w-4 h-4" /> },
]

const TOOL_OPTIONS: { name: ToolName; label: string }[] = [
  { name: 'pattern', label: 'Pattern Scanner' },
  { name: 'slither', label: 'Slither' },
  { name: 'aderyn', label: 'Aderyn' },
  { name: 'mythril', label: 'Mythril' },
  { name: 'echidna', label: 'Echidna' },
  { name: 'foundry', label: 'Foundry' },
  { name: 'halmos', label: 'Halmos' },
  { name: 'certora', label: 'Certora' },
]

export default function AuditConfig({ mode, onModeChange, tools, onToolsChange }: AuditConfigProps) {
  const toggleTool = (tool: ToolName) => {
    if (tools.includes(tool)) {
      onToolsChange(tools.filter((t) => t !== tool))
    } else {
      onToolsChange([...tools, tool])
    }
  }

  return (
    <div className="space-y-6">
      <div>
        <label className="text-[13px] text-text-secondary mb-3 block font-medium">Audit Mode</label>
        <div className="grid grid-cols-3 gap-2">
          {MODES.map((m) => (
            <button
              key={m.value}
              onClick={() => onModeChange(m.value)}
              className={`flex flex-col items-center gap-1.5 p-4 rounded-xl border transition-all duration-200 cursor-pointer ${
                mode === m.value
                  ? 'border-accent/40 bg-accent/8 text-accent shadow-sm shadow-accent/10'
                  : 'border-border bg-surface/30 text-text-secondary hover:bg-surface/60'
              }`}
            >
              {m.icon}
              <span className="text-[13px] font-semibold">{m.label}</span>
              <span className="text-[11px] opacity-60">{m.desc}</span>
            </button>
          ))}
        </div>
      </div>

      <div>
        <label className="text-[13px] text-text-secondary mb-3 block font-medium">Tools</label>
        <div className="flex flex-wrap gap-2">
          {TOOL_OPTIONS.map((tool) => (
            <button
              key={tool.name}
              onClick={() => toggleTool(tool.name)}
              className={`px-3.5 py-1.5 rounded-full text-[12px] font-medium border transition-all duration-200 cursor-pointer ${
                tools.includes(tool.name)
                  ? 'border-accent/40 bg-accent/10 text-accent'
                  : 'border-border bg-surface/30 text-text-secondary hover:bg-surface/60'
              }`}
            >
              {tool.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}
