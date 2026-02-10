import { Link } from 'react-router'
import { ArrowLeft, Shield } from 'lucide-react'

export default function Terms() {
  return (
    <div className="min-h-screen bg-bg-primary p-6">
    <div className="max-w-3xl mx-auto">
      <div className="flex items-center justify-between mb-4">
        <Link
          to="/"
          className="inline-flex items-center gap-1.5 text-[12px] text-text-secondary hover:text-text-primary transition-colors no-underline"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to SolidityGuard
        </Link>
        <Link to="/" className="inline-flex items-center gap-2 text-[14px] font-semibold text-text-primary no-underline">
          <Shield className="w-4 h-4 text-accent" />
          SolidityGuard
        </Link>
      </div>

      <h1 className="text-[20px] font-bold text-text-primary tracking-tight mb-1">
        Terms of Service
      </h1>
      <p className="text-[13px] text-text-secondary mb-6">
        Last updated: February 10, 2026
      </p>

      <div className="glass rounded-xl p-6 space-y-6 text-[13px] text-text-secondary leading-relaxed">
        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">1. Acceptance of Terms</h2>
          <p>
            By accessing or using SolidityGuard (the &quot;Service&quot;), provided by Alt Research Ltd.
            (&quot;Company&quot;, &quot;we&quot;, &quot;us&quot;, or &quot;our&quot;), you agree to be bound by these
            Terms of Service (&quot;Terms&quot;). If you do not agree, do not use the Service.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">2. Description of Service</h2>
          <p>
            SolidityGuard is a smart contract security analysis tool that performs automated
            vulnerability scanning, pattern matching, and report generation for Solidity/EVM smart contracts.
            The Service uses a combination of static analysis tools, symbolic execution, fuzzing, and
            automated pattern detection.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">3. No Substitute for Professional Audit</h2>
          <p>
            The Service is an automated analysis tool and is <strong className="text-text-primary">not a substitute
            for a comprehensive, professional manual security audit</strong>. Smart contract security is complex
            and no automated tool can guarantee the detection of all vulnerabilities. You should always engage
            qualified security professionals for a thorough audit before deploying contracts to mainnet or
            handling significant value.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">4. No Guarantee of Completeness</h2>
          <p>
            While SolidityGuard employs 104 vulnerability patterns and 8 security tools, we make
            <strong className="text-text-primary"> no guarantee that the Service will identify all
            vulnerabilities, bugs, or security issues</strong> in your smart contracts. New attack vectors,
            zero-day exploits, and novel vulnerability patterns may not be covered. The absence of findings
            does not certify a contract as secure.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">5. Use at Your Own Risk</h2>
          <p>
            You acknowledge and agree that your use of the Service is entirely at your own risk. You are
            solely responsible for any decisions you make based on the Service&apos;s output, including but not
            limited to deploying smart contracts, managing funds, or modifying code. Alt Research Ltd. shall
            not be responsible for any actions you take or fail to take based on the results provided by the
            Service.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">6. Disclaimer of Warranties</h2>
          <p>
            THE SERVICE IS PROVIDED <strong className="text-text-primary">&quot;AS IS&quot;</strong> AND
            <strong className="text-text-primary"> &quot;AS AVAILABLE&quot;</strong> WITHOUT WARRANTIES OF ANY
            KIND, WHETHER EXPRESS, IMPLIED, STATUTORY, OR OTHERWISE. TO THE FULLEST EXTENT PERMITTED BY
            APPLICABLE LAW, ALT RESEARCH LTD. DISCLAIMS ALL WARRANTIES, INCLUDING BUT NOT LIMITED TO:
          </p>
          <ul className="list-disc pl-5 mt-2 space-y-1">
            <li>IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NON-INFRINGEMENT</li>
            <li>WARRANTIES THAT THE SERVICE WILL BE UNINTERRUPTED, ERROR-FREE, OR SECURE</li>
            <li>WARRANTIES REGARDING THE ACCURACY, RELIABILITY, OR COMPLETENESS OF ANY RESULTS OR OUTPUT</li>
            <li>WARRANTIES THAT THE SERVICE WILL DETECT ALL VULNERABILITIES OR SECURITY ISSUES</li>
          </ul>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">7. Limitation of Liability</h2>
          <p>
            TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL ALT RESEARCH LTD., ITS
            DIRECTORS, OFFICERS, EMPLOYEES, AGENTS, OR AFFILIATES BE LIABLE FOR ANY INDIRECT, INCIDENTAL,
            SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES, INCLUDING BUT NOT LIMITED TO:
          </p>
          <ul className="list-disc pl-5 mt-2 space-y-1">
            <li>LOSS OF FUNDS, TOKENS, OR DIGITAL ASSETS</li>
            <li>LOSS OF PROFITS, REVENUE, OR BUSINESS OPPORTUNITIES</li>
            <li>LOSS OF DATA OR GOODWILL</li>
            <li>SMART CONTRACT EXPLOITS OR HACKS</li>
            <li>DAMAGES ARISING FROM RELIANCE ON THE SERVICE&apos;S OUTPUT</li>
          </ul>
          <p className="mt-2">
            THIS LIMITATION APPLIES WHETHER THE DAMAGES ARISE FROM USE OR MISUSE OF THE SERVICE, INABILITY
            TO USE THE SERVICE, OR ANY OTHER CAUSE, REGARDLESS OF THE THEORY OF LIABILITY (CONTRACT, TORT,
            OR OTHERWISE), EVEN IF ALT RESEARCH LTD. HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.
          </p>
          <p className="mt-2">
            IN NO EVENT SHALL ALT RESEARCH LTD.&apos;S TOTAL AGGREGATE LIABILITY EXCEED THE AMOUNT YOU PAID
            TO ALT RESEARCH LTD. FOR USE OF THE SERVICE IN THE TWELVE (12) MONTHS PRECEDING THE CLAIM, OR
            ONE HUNDRED US DOLLARS (US$100), WHICHEVER IS GREATER.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">8. Indemnification</h2>
          <p>
            You agree to indemnify, defend, and hold harmless Alt Research Ltd., its directors, officers,
            employees, agents, and affiliates from and against any and all claims, liabilities, damages,
            losses, costs, and expenses (including reasonable attorneys&apos; fees) arising out of or relating to:
          </p>
          <ul className="list-disc pl-5 mt-2 space-y-1">
            <li>Your use of the Service</li>
            <li>Your smart contracts, code, or projects analyzed by the Service</li>
            <li>Any reliance you place on the Service&apos;s output or reports</li>
            <li>Any breach of these Terms by you</li>
            <li>Any third-party claims arising from your deployment of smart contracts</li>
          </ul>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">9. Intellectual Property</h2>
          <p>
            You retain all ownership rights to your smart contract code uploaded for analysis. We do not
            claim any intellectual property rights over your code. The Service, including its vulnerability
            patterns, detection algorithms, and reports, is the intellectual property of Alt Research Ltd.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">10. Modifications to Terms</h2>
          <p>
            We reserve the right to modify these Terms at any time. Changes will be effective upon posting
            to the Service. Your continued use of the Service after changes are posted constitutes acceptance
            of the modified Terms.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">11. Governing Law</h2>
          <p>
            These Terms shall be governed by and construed in accordance with the laws of the jurisdiction
            in which Alt Research Ltd. is incorporated, without regard to conflict of law principles.
          </p>
        </section>

        <section>
          <h2 className="text-[15px] font-semibold text-text-primary mb-2">12. Contact</h2>
          <p>
            For questions about these Terms, contact us at{' '}
            <a href="mailto:maintainers@altresear.ch" className="text-accent hover:text-accent-hover transition-colors">
              maintainers@altresear.ch
            </a>
          </p>
        </section>

        <div className="pt-4 border-t border-border text-[11px] text-text-secondary">
          Alt Research Ltd. &mdash;{' '}
          <a
            href="https://solidityguard.org"
            target="_blank"
            rel="noopener noreferrer"
            className="text-accent hover:text-accent-hover transition-colors"
          >
            solidityguard.org
          </a>
        </div>
      </div>
    </div>
    </div>
  )
}
