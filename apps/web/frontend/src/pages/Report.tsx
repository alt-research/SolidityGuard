import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { api, isTauri } from '../services/api.ts'
import { Download, FileText, FileJson, FileCode, Loader2 } from 'lucide-react'

function renderMarkdown(md: string): string {
  if (!md) return '<p class="text-sm text-text-secondary">No report content available.</p>'
  let html = md
    // Headers
    .replace(/^### (.*$)/gm, '<h3 class="text-base font-semibold text-text-primary mt-6 mb-2">$1</h3>')
    .replace(/^## (.*$)/gm, '<h2 class="text-lg font-bold text-text-primary mt-8 mb-3">$1</h2>')
    .replace(/^# (.*$)/gm, '<h1 class="text-xl font-bold text-text-primary mt-6 mb-4">$1</h1>')
    // Horizontal rules
    .replace(/^---$/gm, '<hr class="border-border my-6" />')
    // Bold
    .replace(/\*\*(.*?)\*\*/g, '<strong class="font-semibold">$1</strong>')
    // Inline code
    .replace(/`([^`]+)`/g, '<code class="bg-bg-tertiary px-1.5 py-0.5 rounded text-xs font-mono text-accent">$1</code>')
    // Table rows — simple handling
    .replace(/^\| (.+) \|$/gm, (match) => {
      const cells = match.split('|').filter(c => c.trim())
      if (cells.every(c => /^[-:\s]+$/.test(c))) {
        return '' // skip separator row
      }
      const isHeader = cells.some(c => c.includes('#') || c.includes('ID') || c.includes('Title') || c.includes('Severity'))
      const tag = isHeader ? 'th' : 'td'
      const cellClass = isHeader
        ? 'px-3 py-2 text-left text-xs font-semibold text-text-secondary uppercase tracking-wider bg-bg-tertiary'
        : 'px-3 py-2 text-sm text-text-primary border-t border-border'
      const row = cells.map(c => `<${tag} class="${cellClass}">${c.trim()}</${tag}>`).join('')
      return `<tr>${row}</tr>`
    })
    // List items
    .replace(/^- (.*$)/gm, '<li class="text-sm text-text-secondary ml-4 list-disc">$1</li>')
    // Paragraphs (lines not starting with < or empty)
    .replace(/^(?!<|$|\s*$)(.+)$/gm, '<p class="text-sm text-text-secondary mb-2">$1</p>')

  // Wrap table rows in table
  if (html.includes('<tr>')) {
    html = html.replace(
      /(<tr>[\s\S]*?<\/tr>(?:\s*<tr>[\s\S]*?<\/tr>)*)/g,
      '<div class="overflow-x-auto mb-4"><table class="w-full border border-border rounded-lg overflow-hidden">$1</table></div>'
    )
  }

  return html
}

export default function Report() {
  const { id } = useParams()
  const [markdown, setMarkdown] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!id) return
    setLoading(true)
    setError(null)

    api.getReportMarkdown(id)
      .then((data: Record<string, unknown>) => {
        setMarkdown((data.report_markdown ?? data.markdown ?? '') as string)
      })
      .catch((err) => {
        setError(err instanceof Error ? err.message : 'Failed to load report')
      })
      .finally(() => setLoading(false))
  }, [id])

  const [exporting, setExporting] = useState(false)

  const handleExport = async (format: string) => {
    if (format === 'json' && id) {
      api.getReport(id).then((report) => {
        const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `audit-report-${id}.json`
        a.click()
        URL.revokeObjectURL(url)
      }).catch(() => {})
      return
    }

    if (format === 'pdf' && id) {
      setExporting(true)
      try {
        if (isTauri) {
          // Desktop: write styled HTML to temp file and open in browser for print/save-as-PDF
          const reportHtml = renderMarkdown(markdown)
          const fullHtml = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>SolidityGuard Audit Report</title>
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 800px; margin: 40px auto; padding: 0 20px; color: #1a1a1a; font-size: 14px; line-height: 1.6; }
  h1 { font-size: 24px; border-bottom: 2px solid #4f46e5; padding-bottom: 8px; }
  h2 { font-size: 18px; margin-top: 32px; color: #1e293b; }
  h3 { font-size: 15px; margin-top: 24px; }
  table { width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 13px; }
  th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
  th { background: #f8fafc; font-weight: 600; }
  code { background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 12px; }
  hr { border: none; border-top: 1px solid #e2e8f0; margin: 24px 0; }
  strong { font-weight: 600; }
  pre { background: #f8fafc; padding: 12px; border-radius: 6px; overflow-x: auto; }
  pre code { background: none; padding: 0; }
  li { margin: 4px 0; }
  @media print { body { margin: 20px; } }
</style>
</head><body>${reportHtml}
<script>window.onload = function() { window.print(); }</script>
</body></html>`
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await (window as any).__TAURI__.core.invoke('export_report_html', { html: fullHtml })
        } else {
          const BASE_URL = import.meta.env.VITE_API_URL || ''
          const token = localStorage.getItem('solidityguard_token')
          const res = await fetch(`${BASE_URL}/api/audit/${encodeURIComponent(id)}/report/pdf`, {
            headers: token ? { Authorization: `Bearer ${token}` } : {},
          })
          if (!res.ok) throw new Error('PDF generation failed')
          const blob = await res.blob()
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = `audit-report-${id.slice(0, 8)}.pdf`
          a.click()
          URL.revokeObjectURL(url)
        }
      } catch {
        setError('PDF export failed. Try exporting as Markdown instead.')
      } finally {
        setExporting(false)
      }
      return
    }

    // Markdown export
    const blob = new Blob([markdown], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `audit-report-${id}.md`
    a.click()
    URL.revokeObjectURL(url)
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-text-secondary gap-2">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading report...
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
    <div className="p-6 max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">Audit Report</h1>
        <div className="flex items-center gap-2">
          <button
            onClick={() => handleExport('md')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface border border-border text-sm text-text-secondary hover:text-text-primary hover:border-text-secondary/30 transition-colors cursor-pointer"
          >
            <FileText className="w-4 h-4" />
            Markdown
          </button>
          <button
            onClick={() => handleExport('json')}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface border border-border text-sm text-text-secondary hover:text-text-primary hover:border-text-secondary/30 transition-colors cursor-pointer"
          >
            <FileJson className="w-4 h-4" />
            JSON
          </button>
          <button
            onClick={() => handleExport('pdf')}
            disabled={exporting}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent text-bg-primary text-sm font-medium hover:bg-accent-hover transition-colors cursor-pointer disabled:opacity-50"
          >
            {exporting ? <Loader2 className="w-4 h-4 animate-spin" /> : <Download className="w-4 h-4" />}
            {exporting ? 'Generating...' : 'Export PDF'}
          </button>
        </div>
      </div>

      <div className="bg-surface rounded-lg border border-border p-8">
        <div
          className="prose-invert max-w-none"
          dangerouslySetInnerHTML={{ __html: renderMarkdown(markdown) }}
        />
      </div>

      <div className="mt-6 flex items-center gap-2 text-xs text-text-secondary">
        <FileCode className="w-3 h-3" />
        <span>Raw Markdown available for integration with CI/CD pipelines</span>
      </div>
    </div>
  )
}
