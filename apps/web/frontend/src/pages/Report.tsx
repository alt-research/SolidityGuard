import { useState, useEffect } from 'react'
import { useParams } from 'react-router'
import { api, isTauri } from '../services/api.ts'
import { Download, FileText, FileJson, FileCode, Loader2 } from 'lucide-react'

/** Generate a PDF from markdown using jsPDF (no canvas, no external deps). */
async function generatePdfFromMarkdown(md: string, filename: string) {
  const { jsPDF } = await import('jspdf')
  const doc = new jsPDF({ unit: 'mm', format: 'a4', orientation: 'portrait' })
  const pageW = doc.internal.pageSize.getWidth()
  const pageH = doc.internal.pageSize.getHeight()
  const marginL = 20, marginR = 20, marginT = 25, marginB = 20
  const contentW = pageW - marginL - marginR
  let y = marginT

  function checkPage(needed: number) {
    if (y + needed > pageH - marginB) {
      doc.addPage()
      y = marginT
    }
  }

  function drawLine() {
    checkPage(6)
    doc.setDrawColor(200, 200, 200)
    doc.setLineWidth(0.3)
    doc.line(marginL, y, pageW - marginR, y)
    y += 4
  }

  function addText(text: string, size: number, style: string, color: [number, number, number], spacing = 1.4) {
    doc.setFontSize(size)
    doc.setFont('helvetica', style)
    doc.setTextColor(...color)
    const clean = text.replace(/\*\*/g, '').replace(/`/g, '')
    const lines = doc.splitTextToSize(clean, contentW)
    const lineH = size * 0.4 * spacing
    for (const line of lines) {
      checkPage(lineH)
      doc.text(line, marginL, y)
      y += lineH
    }
  }

  // Parse and render
  const lines = md.split('\n')
  let i = 0
  while (i < lines.length) {
    const line = lines[i]

    // Skip empty lines
    if (!line.trim()) { y += 2; i++; continue }

    // H1
    if (line.startsWith('# ') && !line.startsWith('## ')) {
      checkPage(12)
      addText(line.slice(2), 18, 'bold', [30, 41, 59])
      doc.setDrawColor(79, 70, 229)
      doc.setLineWidth(0.8)
      doc.line(marginL, y, pageW - marginR, y)
      y += 5
      i++; continue
    }

    // H2
    if (line.startsWith('## ') && !line.startsWith('### ')) {
      checkPage(10)
      y += 4
      addText(line.slice(3), 14, 'bold', [30, 41, 59])
      doc.setDrawColor(226, 232, 240)
      doc.setLineWidth(0.3)
      doc.line(marginL, y, pageW - marginR, y)
      y += 3
      i++; continue
    }

    // H3
    if (line.startsWith('### ')) {
      checkPage(8)
      y += 3
      addText(line.slice(4), 11, 'bold', [51, 65, 85])
      y += 1
      i++; continue
    }

    // HR
    if (line.trim() === '---') {
      drawLine()
      i++; continue
    }

    // Table
    if (line.startsWith('|')) {
      const tableRows: string[][] = []
      while (i < lines.length && lines[i].startsWith('|')) {
        const cells = lines[i].split('|').filter(c => c.trim()).map(c => c.trim())
        // Skip separator row
        if (cells.every(c => /^[-:\s]+$/.test(c))) { i++; continue }
        tableRows.push(cells)
        i++
      }
      if (tableRows.length === 0) continue

      const colCount = tableRows[0].length
      const colW = contentW / colCount
      const cellPad = 2
      const cellFontSize = 7.5
      const cellLineH = 3.5

      for (let r = 0; r < tableRows.length; r++) {
        const row = tableRows[r]
        // Calculate max lines in this row
        doc.setFontSize(cellFontSize)
        let maxLines = 1
        for (let c = 0; c < row.length; c++) {
          const cellText = (row[c] || '').replace(/`/g, '')
          const wrapped = doc.splitTextToSize(cellText, colW - cellPad * 2)
          maxLines = Math.max(maxLines, wrapped.length)
        }
        const rowH = maxLines * cellLineH + cellPad * 2
        checkPage(rowH)

        for (let c = 0; c < colCount; c++) {
          const x = marginL + c * colW
          // Background for header
          if (r === 0) {
            doc.setFillColor(248, 250, 252)
            doc.rect(x, y, colW, rowH, 'F')
          }
          // Border
          doc.setDrawColor(226, 232, 240)
          doc.setLineWidth(0.2)
          doc.rect(x, y, colW, rowH)
          // Text
          doc.setFont('helvetica', r === 0 ? 'bold' : 'normal')
          doc.setFontSize(cellFontSize)
          doc.setTextColor(26, 26, 26)
          const cellText = (row[c] || '').replace(/`/g, '')
          const wrapped = doc.splitTextToSize(cellText, colW - cellPad * 2)
          for (let l = 0; l < wrapped.length; l++) {
            doc.text(wrapped[l], x + cellPad, y + cellPad + cellLineH * (l + 0.7))
          }
        }
        y += rowH
      }
      y += 3
      continue
    }

    // List item
    if (line.startsWith('- ')) {
      checkPage(5)
      doc.setFontSize(9)
      doc.setFont('helvetica', 'normal')
      doc.setTextColor(80, 80, 80)
      doc.text('\u2022', marginL, y)
      const itemLines = doc.splitTextToSize(line.slice(2).replace(/\*\*/g, '').replace(/`/g, ''), contentW - 5)
      for (const il of itemLines) {
        checkPage(4)
        doc.text(il, marginL + 5, y)
        y += 3.8
      }
      i++; continue
    }

    // Bold-prefixed lines (like **Date:** value)
    if (line.startsWith('**')) {
      checkPage(5)
      const clean = line.replace(/\*\*/g, '').replace(/`/g, '')
      addText(clean, 9, 'normal', [60, 60, 60])
      y += 1
      i++; continue
    }

    // Regular paragraph
    addText(line, 9, 'normal', [60, 60, 60])
    y += 1.5
    i++
  }

  // Footer on each page
  const totalPages = doc.getNumberOfPages()
  for (let p = 1; p <= totalPages; p++) {
    doc.setPage(p)
    doc.setFontSize(7)
    doc.setFont('helvetica', 'normal')
    doc.setTextColor(150, 150, 150)
    doc.text('Generated by SolidityGuard', marginL, pageH - 10)
    doc.text(`Page ${p} of ${totalPages}`, pageW - marginR, pageH - 10, { align: 'right' })
  }

  doc.save(filename)
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
          // Desktop: generate PDF client-side using jsPDF (no external deps)
          await generatePdfFromMarkdown(markdown, `audit-report-${id.slice(0, 8)}.pdf`)
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
