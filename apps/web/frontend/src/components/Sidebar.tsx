import { useState } from 'react'
import { NavLink, useParams } from 'react-router'
import { useAuthContext } from '../contexts/AuthContext'
import {
  Shield,
  LayoutDashboard,
  FilePlus,
  AlertTriangle,
  FileText,
  BookOpen,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  Scale,
  ShieldCheck,
} from 'lucide-react'

const NAV_ITEMS = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', exact: true },
  { to: '/new', icon: FilePlus, label: 'New Scan' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings', needsAudit: true },
  { to: '/report', icon: FileText, label: 'Report', needsAudit: true },
  { to: '/patterns', icon: BookOpen, label: 'Patterns' },
  { to: '/settings', icon: Settings, label: 'Settings' },
]

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false)
  const { user, logout } = useAuthContext()
  const { id: auditId } = useParams()

  const resolveLink = (item: typeof NAV_ITEMS[number]) => {
    if (item.needsAudit && auditId) {
      return `/audit/${auditId}${item.to === '/findings' ? '/findings' : '/report'}`
    }
    return item.to
  }

  return (
    <aside
      className={`shrink-0 h-screen sticky top-0 flex flex-col border-r border-border bg-bg-secondary/60 backdrop-blur-xl transition-all duration-200 ${
        collapsed ? 'w-16' : 'w-56'
      }`}
    >
      {/* Logo */}
      <div className="h-14 flex items-center gap-2.5 px-4 border-b border-border shrink-0">
        <Shield className="w-5 h-5 text-accent shrink-0" />
        {!collapsed && (
          <span className="text-[15px] font-semibold text-text-primary tracking-tight whitespace-nowrap">
            SolidityGuard
          </span>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-3 px-2 space-y-0.5 overflow-y-auto">
        {NAV_ITEMS.map((item) => {
          const Icon = item.icon
          const isDisabled = item.needsAudit && !auditId
          if (isDisabled) {
            return (
              <div
                key={item.to}
                className={`flex items-center gap-2.5 rounded-lg text-[13px] font-medium text-text-secondary/40 cursor-not-allowed ${
                  collapsed ? 'justify-center px-2 py-2.5' : 'px-3 py-2.5'
                }`}
                title={collapsed ? item.label : undefined}
              >
                <Icon className="w-[18px] h-[18px] shrink-0" />
                {!collapsed && <span>{item.label}</span>}
              </div>
            )
          }
          return (
            <NavLink
              key={item.to}
              to={resolveLink(item)}
              end={item.exact}
              className={({ isActive }) =>
                `flex items-center gap-2.5 rounded-lg text-[13px] font-medium transition-colors duration-150 no-underline ${
                  collapsed ? 'justify-center px-2 py-2.5' : 'px-3 py-2.5'
                } ${
                  isActive
                    ? 'bg-accent/10 text-accent'
                    : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover/30'
                }`
              }
              title={collapsed ? item.label : undefined}
            >
              <Icon className="w-[18px] h-[18px] shrink-0" />
              {!collapsed && <span>{item.label}</span>}
            </NavLink>
          )
        })}
      </nav>

      {/* Legal links */}
      <div className="px-2 pb-1 space-y-0.5">
        <NavLink
          to="/terms"
          className={({ isActive }) =>
            `flex items-center gap-2.5 rounded-lg text-[12px] font-medium transition-colors duration-150 no-underline ${
              collapsed ? 'justify-center px-2 py-2' : 'px-3 py-2'
            } ${
              isActive
                ? 'bg-accent/10 text-accent'
                : 'text-text-secondary/60 hover:text-text-secondary hover:bg-surface-hover/30'
            }`
          }
          title={collapsed ? 'Terms of Service' : undefined}
        >
          <Scale className="w-[15px] h-[15px] shrink-0" />
          {!collapsed && <span>Terms</span>}
        </NavLink>
        <NavLink
          to="/privacy"
          className={({ isActive }) =>
            `flex items-center gap-2.5 rounded-lg text-[12px] font-medium transition-colors duration-150 no-underline ${
              collapsed ? 'justify-center px-2 py-2' : 'px-3 py-2'
            } ${
              isActive
                ? 'bg-accent/10 text-accent'
                : 'text-text-secondary/60 hover:text-text-secondary hover:bg-surface-hover/30'
            }`
          }
          title={collapsed ? 'Privacy Policy' : undefined}
        >
          <ShieldCheck className="w-[15px] h-[15px] shrink-0" />
          {!collapsed && <span>Privacy</span>}
        </NavLink>
      </div>

      {/* Collapse toggle */}
      <button
        onClick={() => setCollapsed(!collapsed)}
        className="mx-2 mb-2 flex items-center justify-center h-8 rounded-lg text-text-secondary hover:text-text-primary hover:bg-surface-hover/30 transition-colors cursor-pointer"
        title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        {collapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
      </button>

      {/* User section */}
      {user && (
        <div className="border-t border-border px-3 py-3 shrink-0">
          <div className={`flex items-center ${collapsed ? 'justify-center' : 'gap-2.5'}`}>
            {user.picture ? (
              <img
                src={user.picture}
                alt=""
                className="w-7 h-7 rounded-full ring-1 ring-border-strong shrink-0"
                referrerPolicy="no-referrer"
              />
            ) : (
              <div className="w-7 h-7 rounded-full bg-accent/20 flex items-center justify-center shrink-0">
                <span className="text-[11px] font-semibold text-accent">
                  {(user.name || user.email || '?')[0].toUpperCase()}
                </span>
              </div>
            )}
            {!collapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-[12px] font-medium text-text-primary truncate">
                  {user.name || user.email}
                </p>
                <p className="text-[10px] text-text-secondary truncate">{user.email}</p>
              </div>
            )}
            {!collapsed && (
              <button
                onClick={logout}
                className="text-text-secondary hover:text-text-primary transition-colors cursor-pointer p-1"
                title="Sign out"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>
        </div>
      )}
    </aside>
  )
}
