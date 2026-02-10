import { Shield } from 'lucide-react'
import { useAuthContext } from '../contexts/AuthContext'

export default function Login() {
  const { login } = useAuthContext()

  return (
    <div className="min-h-screen bg-bg-primary flex items-center justify-center relative overflow-hidden">
      {/* Background gradient blobs */}
      <div className="absolute top-[-20%] left-[-10%] w-[500px] h-[500px] rounded-full bg-accent/5 blur-[120px]" />
      <div className="absolute bottom-[-20%] right-[-10%] w-[400px] h-[400px] rounded-full bg-severity-critical/5 blur-[120px]" />

      <div className="glass rounded-2xl p-10 max-w-sm w-full mx-6 text-center relative z-10">
        <div className="inline-flex items-center justify-center w-16 h-16 rounded-2xl bg-accent/10 mb-6">
          <Shield className="w-8 h-8 text-accent" />
        </div>

        <h1 className="text-[24px] font-bold text-text-primary tracking-tight mb-1">SolidityGuard</h1>
        <p className="text-[13px] text-text-secondary mb-8 leading-relaxed">
          AI-powered smart contract security audit
        </p>

        <button
          onClick={login}
          className="w-full flex items-center justify-center gap-3 py-3 rounded-xl bg-white text-[#1f1f1f] font-semibold text-[14px] hover:bg-white/90 transition-all duration-200 cursor-pointer active:scale-[0.98] shadow-lg"
        >
          <svg className="w-[18px] h-[18px]" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Continue with Google
        </button>

        <p className="text-[11px] text-text-secondary mt-6 opacity-60">
          104 vulnerability patterns &middot; 8 analysis tools
        </p>
      </div>
    </div>
  )
}
