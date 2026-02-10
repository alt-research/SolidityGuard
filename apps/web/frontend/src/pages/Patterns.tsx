import { useState, useMemo, useEffect } from 'react'
import type { Severity, VulnPattern } from '../lib/types.ts'
import { SEVERITY_ORDER, CATEGORIES } from '../lib/types.ts'
import { api } from '../services/api.ts'
import PatternCard from '../components/PatternCard.tsx'
import { Search, Filter, Loader2 } from 'lucide-react'

export default function Patterns() {
  const [search, setSearch] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState<Severity | ''>('')
  const [patterns, setPatterns] = useState<VulnPattern[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.getPatterns()
      .then(setPatterns)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const filtered = useMemo(() => {
    return patterns.filter((p) => {
      if (search) {
        const q = search.toLowerCase()
        if (
          !p.id.toLowerCase().includes(q) &&
          !p.name.toLowerCase().includes(q) &&
          !p.description.toLowerCase().includes(q)
        ) return false
      }
      if (selectedCategory && p.category !== selectedCategory) return false
      if (selectedSeverity && p.severity !== selectedSeverity) return false
      return true
    })
  }, [patterns, search, selectedCategory, selectedSeverity])

  const categoryCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    patterns.forEach((p) => {
      counts[p.category] = (counts[p.category] || 0) + 1
    })
    return counts
  }, [patterns])

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24 text-text-secondary gap-2">
        <Loader2 className="w-5 h-5 animate-spin" />
        Loading patterns...
      </div>
    )
  }

  return (
    <div className="p-6">
      <div className="mb-6">
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight mb-1">Vulnerability Patterns</h1>
        <p className="text-[13px] text-text-secondary">
          {patterns.length} patterns covering reentrancy, access control, DeFi, proxy, oracle,
          transient storage, account abstraction, and more.
        </p>
      </div>

      <div className="flex flex-wrap items-center gap-3 mb-6">
        <div className="relative flex-1 min-w-[250px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-secondary" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search patterns by ID, name, or description..."
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-3 py-2 text-sm text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent"
          />
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-4 h-4 text-text-secondary" />
          <select
            value={selectedCategory}
            onChange={(e) => setSelectedCategory(e.target.value)}
            className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text-primary cursor-pointer focus:outline-none focus:border-accent"
          >
            <option value="">All Categories</option>
            {CATEGORIES.map((cat) => (
              <option key={cat} value={cat}>
                {cat} ({categoryCounts[cat] || 0})
              </option>
            ))}
          </select>

          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value as Severity | '')}
            className="bg-surface border border-border rounded-lg px-3 py-2 text-sm text-text-primary cursor-pointer focus:outline-none focus:border-accent"
          >
            <option value="">All Severities</option>
            {SEVERITY_ORDER.map((sev) => (
              <option key={sev} value={sev}>{sev}</option>
            ))}
          </select>
        </div>
      </div>

      <div className="text-xs text-text-secondary mb-3">
        Showing {filtered.length} of {patterns.length} patterns
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
        {filtered.map((pattern) => (
          <PatternCard key={pattern.id} pattern={pattern} />
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-16 text-text-secondary text-sm">
          No patterns match your search
        </div>
      )}
    </div>
  )
}
