import { useNavigate, Link } from 'react-router'
import { useAuthContext } from '../contexts/AuthContext'
import {
  Shield,
  FilePlus,
  ArrowRight,
  Zap,
  Lock,
  Eye,
} from 'lucide-react'

export default function Dashboard() {
  const navigate = useNavigate()
  const { user } = useAuthContext()

  return (
    <div className="p-6 space-y-6 max-w-4xl">
      {/* Welcome */}
      <div>
        <h1 className="text-[20px] font-bold text-text-primary tracking-tight">
          Welcome{user?.name ? `, ${user.name.split(' ')[0]}` : ''}
        </h1>
        <p className="text-[13px] text-text-secondary mt-0.5">
          AI-powered smart contract security auditing
        </p>
      </div>

      {/* Hero action */}
      <div className="glass rounded-xl p-8 text-center">
        <div className="w-14 h-14 rounded-2xl bg-accent/10 flex items-center justify-center mx-auto mb-4">
          <Shield className="w-7 h-7 text-accent" />
        </div>
        <h2 className="text-[17px] font-bold text-text-primary mb-2">
          Start a Security Audit
        </h2>
        <p className="text-[13px] text-text-secondary max-w-md mx-auto mb-6">
          Upload your Solidity contracts and get a comprehensive security analysis powered by 104 vulnerability patterns and 8 security tools.
        </p>
        <button
          onClick={() => navigate('/new')}
          className="inline-flex items-center gap-2.5 px-6 py-3 rounded-xl bg-accent hover:bg-accent-hover text-white text-[14px] font-semibold shadow-lg shadow-accent/20 active:scale-[0.98] transition-all duration-200 cursor-pointer"
        >
          <FilePlus className="w-4.5 h-4.5" />
          New Audit
          <ArrowRight className="w-4 h-4" />
        </button>
      </div>

      {/* Features */}
      <div className="grid grid-cols-3 gap-4">
        <div className="glass rounded-xl p-5">
          <div className="w-9 h-9 rounded-lg bg-severity-critical/10 flex items-center justify-center mb-3">
            <Zap className="w-4.5 h-4.5 text-severity-critical" />
          </div>
          <h3 className="text-[14px] font-semibold text-text-primary mb-1">104 Patterns</h3>
          <p className="text-[12px] text-text-secondary leading-relaxed">
            From reentrancy to EIP-7702, covering OWASP Smart Contract Top 10 2025.
          </p>
          <button
            onClick={() => navigate('/patterns')}
            className="mt-3 text-[12px] text-accent hover:text-accent-hover transition-colors cursor-pointer flex items-center gap-1"
          >
            Browse patterns <ArrowRight className="w-3 h-3" />
          </button>
        </div>

        <div className="glass rounded-xl p-5">
          <div className="w-9 h-9 rounded-lg bg-accent/10 flex items-center justify-center mb-3">
            <Lock className="w-4.5 h-4.5 text-accent" />
          </div>
          <h3 className="text-[14px] font-semibold text-text-primary mb-1">8 Security Tools</h3>
          <p className="text-[12px] text-text-secondary leading-relaxed">
            Slither, Mythril, Aderyn, Echidna, Foundry, Medusa, Halmos, and Certora.
          </p>
        </div>

        <div className="glass rounded-xl p-5">
          <div className="w-9 h-9 rounded-lg bg-severity-low/10 flex items-center justify-center mb-3">
            <Eye className="w-4.5 h-4.5 text-severity-low" />
          </div>
          <h3 className="text-[14px] font-semibold text-text-primary mb-1">CTF Validated</h3>
          <p className="text-[12px] text-text-secondary leading-relaxed">
            100% detection on DeFiVulnLabs (56/56) and Paradigm CTF (24/24 static).
          </p>
        </div>
      </div>

      {/* Disclaimer */}
      <div className="text-[11px] text-text-secondary/60 leading-relaxed pt-2">
        SolidityGuard is provided &quot;as is&quot; without warranties of any kind. It is not a substitute for
        a professional manual security audit and does not guarantee the detection of all vulnerabilities.
        Use at your own risk.{' '}
        <Link to="/terms" className="text-text-secondary hover:text-text-primary transition-colors">
          Terms
        </Link>
        {' '}&middot;{' '}
        <Link to="/privacy" className="text-text-secondary hover:text-text-primary transition-colors">
          Privacy
        </Link>
      </div>
    </div>
  )
}
