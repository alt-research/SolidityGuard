import { useState } from 'react'
import { useNavigate } from 'react-router'
import type { AuditMode, ToolName } from '../lib/types.ts'
import { api, isTauri, selectDirectory } from '../services/api.ts'
import FileUpload from '../components/FileUpload.tsx'
import AuditConfig from '../components/AuditConfig.tsx'
import { Play, Loader2, FolderOpen } from 'lucide-react'

export default function Home() {
  const navigate = useNavigate()
  const [files, setFiles] = useState<File[]>([])
  const [dirPath, setDirPath] = useState<string | null>(null)
  const [mode, setMode] = useState<AuditMode>('standard')
  const [tools, setTools] = useState<ToolName[]>(['pattern', 'slither', 'aderyn'])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSelectDir = async () => {
    try {
      const path = await selectDirectory()
      setDirPath(path)
      setError(null)
    } catch {
      // User cancelled or error
    }
  }

  const handleStartAudit = async () => {
    setLoading(true)
    setError(null)
    try {
      if (isTauri && dirPath) {
        const result = await api.startLocalScan(dirPath, tools)
        navigate(`/audit/${result.id}`)
      } else if (files.length > 0) {
        const { id } = await api.startAudit(files, { mode, tools })
        navigate(`/audit/${id}`)
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to start audit')
      setLoading(false)
    }
  }

  const canStart = isTauri ? !!dirPath : files.length > 0

  return (
    <div className="p-6 max-w-2xl space-y-6">
      <div>
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">New Scan</h1>
        <p className="text-[13px] text-text-secondary mt-0.5">
          {isTauri ? 'Select a local contracts directory and configure your audit' : 'Upload contracts and configure your audit'}
        </p>
      </div>

      <div className="glass rounded-xl p-6 space-y-6">
        {isTauri ? (
          <div className="space-y-3">
            <label className="text-[13px] font-medium text-text-primary">Contracts Directory</label>
            <div className="flex items-center gap-3">
              <button
                onClick={handleSelectDir}
                className="flex items-center gap-2 px-4 py-2.5 rounded-xl bg-surface-hover/50 border border-border hover:border-accent/40 text-[13px] text-text-secondary hover:text-text-primary transition-all cursor-pointer"
              >
                <FolderOpen className="w-4 h-4" />
                Select Directory
              </button>
              {dirPath && (
                <span className="text-[13px] text-accent truncate max-w-[300px]" title={dirPath}>
                  {dirPath}
                </span>
              )}
            </div>
          </div>
        ) : (
          <FileUpload files={files} onFilesChange={setFiles} />
        )}

        <AuditConfig mode={mode} onModeChange={setMode} tools={tools} onToolsChange={setTools} />

        {error && (
          <div className="text-[13px] text-severity-critical bg-severity-critical/8 border border-severity-critical/15 rounded-xl px-4 py-3">
            {error}
          </div>
        )}

        <button
          onClick={handleStartAudit}
          disabled={!canStart || loading}
          className={`w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl font-semibold text-[15px] transition-all duration-200 cursor-pointer ${
            canStart && !loading
              ? 'bg-accent hover:bg-accent-hover text-white shadow-lg shadow-accent/20 active:scale-[0.98]'
              : 'bg-bg-tertiary text-text-secondary cursor-not-allowed'
          }`}
        >
          {loading ? (
            <>
              <Loader2 className="w-[18px] h-[18px] animate-spin" />
              Scanning...
            </>
          ) : (
            <>
              <Play className="w-[18px] h-[18px]" />
              Start Audit
            </>
          )}
        </button>
      </div>
    </div>
  )
}
