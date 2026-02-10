import { Link } from 'react-router'
import { useAuthContext } from '../contexts/AuthContext'
import { useTheme } from '../contexts/ThemeContext'
import { LogOut, Shield, ExternalLink, Sun, Moon, Scale, ShieldCheck } from 'lucide-react'

export default function Settings() {
  const { user, logout } = useAuthContext()
  const { theme, toggleTheme } = useTheme()

  return (
    <div className="p-6 max-w-2xl space-y-6">
      <div>
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">Settings</h1>
        <p className="text-[13px] text-text-secondary mt-0.5">Account and preferences</p>
      </div>

      {/* Appearance */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h3 className="text-[14px] font-semibold text-text-primary">Appearance</h3>
        </div>
        <div className="p-5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {theme === 'dark' ? <Moon className="w-5 h-5 text-text-secondary" /> : <Sun className="w-5 h-5 text-severity-medium" />}
              <div>
                <p className="text-[13px] font-medium text-text-primary">
                  {theme === 'dark' ? 'Dark Mode' : 'Light Mode'}
                </p>
                <p className="text-[11px] text-text-secondary">
                  {theme === 'dark' ? 'Optimized for low-light environments' : 'Optimized for bright environments'}
                </p>
              </div>
            </div>
            <button
              onClick={toggleTheme}
              className={`relative w-11 h-6 rounded-full transition-colors duration-200 cursor-pointer ${
                theme === 'light' ? 'bg-accent' : 'bg-surface'
              }`}
            >
              <span
                className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-text-primary transition-transform duration-200 ${
                  theme === 'light' ? 'translate-x-5' : 'translate-x-0'
                }`}
              />
            </button>
          </div>
        </div>
      </div>

      {/* Account */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h3 className="text-[14px] font-semibold text-text-primary">Account</h3>
        </div>
        <div className="p-5 space-y-4">
          {user && (
            <div className="flex items-center gap-4">
              {user.picture ? (
                <img src={user.picture} alt="" className="w-12 h-12 rounded-full ring-1 ring-border-strong" referrerPolicy="no-referrer" />
              ) : (
                <div className="w-12 h-12 rounded-full bg-accent/20 flex items-center justify-center">
                  <span className="text-[16px] font-semibold text-accent">
                    {(user.name || user.email || '?')[0].toUpperCase()}
                  </span>
                </div>
              )}
              <div>
                <p className="text-[14px] font-medium text-text-primary">{user.name}</p>
                <p className="text-[12px] text-text-secondary">{user.email}</p>
              </div>
            </div>
          )}
          <button
            onClick={logout}
            className="flex items-center gap-2 px-4 py-2.5 rounded-xl border border-border text-[13px] font-medium text-severity-critical hover:bg-severity-critical/5 transition-colors cursor-pointer"
          >
            <LogOut className="w-4 h-4" />
            Sign Out
          </button>
        </div>
      </div>

      {/* About */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h3 className="text-[14px] font-semibold text-text-primary">About</h3>
        </div>
        <div className="p-5 space-y-3">
          <div className="flex items-center gap-2.5">
            <Shield className="w-5 h-5 text-accent" />
            <span className="text-[14px] font-semibold text-text-primary">SolidityGuard v1.0</span>
          </div>
          <p className="text-[13px] text-text-secondary leading-relaxed">
            Smart contract security audit tool with 104 vulnerability patterns,
            8 analysis tools, and multi-agent team architecture.
          </p>
          <div className="flex flex-wrap gap-2 pt-1">
            <a
              href="https://github.com/alt-research/SolidityGuard"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface/50 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
            >
              GitHub
              <ExternalLink className="w-3 h-3" />
            </a>
            <a
              href="https://solidityguard.org"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface/50 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
            >
              Website
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Legal */}
      <div className="glass rounded-xl overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <h3 className="text-[14px] font-semibold text-text-primary">Legal</h3>
        </div>
        <div className="p-5 space-y-3">
          <p className="text-[12px] text-text-secondary leading-relaxed">
            SolidityGuard is provided &quot;as is&quot; by Alt Research Ltd. It is not a substitute for a
            professional manual security audit.
          </p>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/terms"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface/50 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
            >
              <Scale className="w-3 h-3" />
              Terms of Service
            </Link>
            <Link
              to="/privacy"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface/50 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
            >
              <ShieldCheck className="w-3 h-3" />
              Privacy Policy
            </Link>
            <a
              href="mailto:maintainers@altresear.ch"
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface/50 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
            >
              Contact
              <ExternalLink className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>
    </div>
  )
}
