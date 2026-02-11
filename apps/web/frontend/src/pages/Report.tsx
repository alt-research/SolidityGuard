import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { api, isTauri } from '../services/api.ts'
import { Download, FileText, FileJson, FileCode, Loader2 } from 'lucide-react'

/** Build print-ready HTML for PDF generation (light theme, A4 styled). */
function buildPdfHtml(md: string): string {
  if (!md) return ''
  let html = md
    .replace(/^### (.*$)/gm, '<h3>$1</h3>')
    .replace(/^## (.*$)/gm, '<h2>$1</h2>')
    .replace(/^# (.*$)/gm, '<h1>$1</h1>')
    .replace(/^---$/gm, '<hr />')
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/^\| (.+) \|$/gm, (match) => {
      const cells = match.split('|').filter(c => c.trim())
      if (cells.every(c => /^[-:\s]+$/.test(c))) return ''
      const isHeader = cells.some(c => c.includes('#') || c.includes('ID') || c.includes('Title') || c.includes('Severity'))
      const tag = isHeader ? 'th' : 'td'
      return `<tr>${cells.map(c => `<${tag}>${c.trim()}</${tag}>`).join('')}</tr>`
    })
    .replace(/^- (.*$)/gm, '<li>$1</li>')
    .replace(/^(?!<|$|\s*$)(.+)$/gm, '<p>$1</p>')
  if (html.includes('<tr>')) {
    html = html.replace(
      /(<tr>[\s\S]*?<\/tr>(?:\s*<tr>[\s\S]*?<\/tr>)*)/g,
      '<table>$1</table>'
    )
  }
  return html
}

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
          // Desktop: generate PDF client-side using html2pdf.js (no Python dependency)
          const html2pdf = (await import('html2pdf.js')).default
          const container = document.createElement('div')
          container.innerHTML = buildPdfHtml(markdown)
          container.style.cssText = `
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 700px; margin: 0 auto; padding: 20px; color: #1a1a1a;
            font-size: 13px; line-height: 1.6; position: absolute; left: -9999px;
          `
          // Apply PDF styles to elements
          container.querySelectorAll('h1').forEach(el => {
            (el as HTMLElement).style.cssText = 'font-size: 22px; border-bottom: 2px solid #4f46e5; padding-bottom: 6px; margin-top: 0;'
          })
          container.querySelectorAll('h2').forEach(el => {
            (el as HTMLElement).style.cssText = 'font-size: 16px; margin-top: 28px; color: #1e293b; border-bottom: 1px solid #e2e8f0; padding-bottom: 4px;'
          })
          container.querySelectorAll('h3').forEach(el => {
            (el as HTMLElement).style.cssText = 'font-size: 14px; margin-top: 20px; color: #334155;'
          })
          container.querySelectorAll('table').forEach(el => {
            (el as HTMLElement).style.cssText = 'width: 100%; border-collapse: collapse; margin: 12px 0; font-size: 11px;'
          })
          container.querySelectorAll('th, td').forEach(el => {
            (el as HTMLElement).style.cssText = 'border: 1px solid #e2e8f0; padding: 5px 8px; text-align: left;'
          })
          container.querySelectorAll('th').forEach(el => {
            (el as HTMLElement).style.cssText += 'background: #f8fafc; font-weight: 600;'
          })
          container.querySelectorAll('code').forEach(el => {
            (el as HTMLElement).style.cssText = 'background: #f1f5f9; padding: 1px 4px; border-radius: 3px; font-size: 11px; font-family: Menlo, Consolas, monospace;'
          })
          container.querySelectorAll('hr').forEach(el => {
            (el as HTMLElement).style.cssText = 'border: none; border-top: 1px solid #e2e8f0; margin: 20px 0;'
          })
          document.body.appendChild(container)

          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          await (html2pdf() as any).set({
            margin: [15, 15, 20, 15],
            filename: `audit-report-${id.slice(0, 8)}.pdf`,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { scale: 2, useCORS: true, logging: false },
            jsPDF: { unit: 'mm', format: 'a4', orientation: 'portrait' },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] },
          }).from(container).save()

          document.body.removeChild(container)
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
