import { Routes, Route, Navigate } from 'react-router'
import { useAuthContext } from './contexts/AuthContext'
import Layout from './components/Layout'
import Login from './pages/Login'
import Dashboard from './pages/Dashboard'
import Home from './pages/Home'
import Audit from './pages/Audit'
import Findings from './pages/Findings'
import Report from './pages/Report'
import Patterns from './pages/Patterns'
import Settings from './pages/Settings'
import Terms from './pages/Terms'
import Privacy from './pages/Privacy'
import { Loader2 } from 'lucide-react'

function AuthGate({ children }: { children: React.ReactNode }) {
  const { user, loading } = useAuthContext()

  if (loading) {
    return (
      <div className="min-h-screen bg-bg-primary flex items-center justify-center">
        <Loader2 className="w-6 h-6 text-accent animate-spin" />
      </div>
    )
  }

  if (!user) {
    return <Login />
  }

  return <>{children}</>
}

export default function App() {
  return (
    <Routes>
      {/* Public pages — no auth required */}
      <Route path="/terms" element={<Terms />} />
      <Route path="/privacy" element={<Privacy />} />

      {/* Authenticated pages */}
      <Route
        element={
          <AuthGate>
            <Layout />
          </AuthGate>
        }
      >
        <Route path="/" element={<Dashboard />} />
        <Route path="/new" element={<Home />} />
        <Route path="/audit/:id" element={<Audit />} />
        <Route path="/audit/:id/findings" element={<Findings />} />
        <Route path="/audit/:id/report" element={<Report />} />
        <Route path="/patterns" element={<Patterns />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Route>
    </Routes>
  )
}
