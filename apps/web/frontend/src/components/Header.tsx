import { useLocation } from 'react-router'
import { useTheme } from '../contexts/ThemeContext'
import { Search, Sun, Moon } from 'lucide-react'

const CRUMB_LABELS: Record<string, string> = {
  '': 'Dashboard',
  new: 'New Scan',
  audit: 'Audit',
  findings: 'Findings',
  report: 'Report',
  patterns: 'Patterns',
  settings: 'Settings',
}

export default function Header() {
  const location = useLocation()
  const { theme, toggleTheme } = useTheme()

  const crumbs = location.pathname
    .split('/')
    .filter(Boolean)
    .map((seg) => CRUMB_LABELS[seg] || seg)

  if (crumbs.length === 0) crumbs.push('Dashboard')

  return (
    <header className="h-14 shrink-0 border-b border-border bg-bg-secondary/40 backdrop-blur-xl flex items-center justify-between px-6">
      {/* Breadcrumbs */}
      <div className="flex items-center gap-1.5 text-[13px]">
        {crumbs.map((crumb, i) => (
          <span key={i} className="flex items-center gap-1.5">
            {i > 0 && <span className="text-text-secondary/40">/</span>}
            <span
              className={
                i === crumbs.length - 1
                  ? 'text-text-primary font-medium'
                  : 'text-text-secondary'
              }
            >
              {crumb}
            </span>
          </span>
        ))}
      </div>

      <div className="flex items-center gap-3">
        {/* Theme toggle */}
        <button
          onClick={toggleTheme}
          className="w-8 h-8 flex items-center justify-center rounded-lg text-text-secondary hover:text-text-primary hover:bg-surface-hover/50 transition-colors cursor-pointer"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
        </button>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-text-secondary" />
          <input
            type="text"
            placeholder="Search findings..."
            className="h-8 w-48 pl-8 pr-3 rounded-lg bg-surface/50 border border-border text-[12px] text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent/40 transition-colors"
          />
        </div>
      </div>
    </header>
  )
}
