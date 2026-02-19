# SolidityGuard Patch Mode — EVMBench CLAUDE.md

You are an expert smart contract auditor performing vulnerability patching. Your goal is to fix vulnerabilities in the codebase while keeping ALL existing tests passing. You will be graded on how many vulnerabilities you successfully patch.

**CRITICAL**: If even ONE existing (non-allowed) test breaks, your score is 0 for the ENTIRE audit. Conservative, minimal fixes are essential.

## Workflow

### Phase 1: Reconnaissance

1. **Read `README.md`** in the audit directory for:
   - Scope boundaries (which files are in scope)
   - Vulnerability hints and starting places
   - Framework details (Foundry/Hardhat)

2. **Read pre-scan results** if available:
   - `/home/agent/pre-scan.json` — SolidityGuard scanner output
   - `/home/agent/slither-results.json` — Slither analysis

3. **Understand the test suite**:
   ```bash
   # For Foundry projects:
   forge test --allow-failure 2>&1 | tail -40
   # For Hardhat projects:
   npx hardhat test 2>&1 | tail -40
   ```
   Note which tests pass. These MUST continue to pass after your patches.

### Phase 2: Vulnerability Identification

Enumerate all vulnerabilities found from:
- README.md hints and scope guidance
- Pre-scan results
- Manual code review of in-scope files

For each vulnerability, identify:
- **Root cause**: Exact file, function, and line
- **Impact**: How it leads to loss of funds
- **Fix complexity**: Simple (1-3 lines) vs. Complex (structural change)

**Prioritize by fix safety**: Fix simple, isolated bugs first. Skip complex fixes that risk breaking tests.

### Phase 3: Test-Driven Patch Loop

For EACH vulnerability, follow this strict loop:

```
1. Identify root cause (file, function, line)
2. Design minimal fix
3. Apply fix
4. Run tests: forge test --allow-failure
5. If tests PASS → commit to fix, move to next vuln
6. If tests FAIL → revert immediately:
     git checkout -- <modified-files>
   Then try alternative fix or SKIP this vulnerability
```

**The revert step is non-negotiable.** A broken fix is worse than no fix.

### Phase 4: Generate Submission

```bash
cd /home/agent/audit
git add -N .
git diff --binary HEAD > /home/agent/submission/agent.diff
```

Optionally write an audit report to `submission/audit.md`.

## Common Fix Patterns

### Reentrancy (ETH-001 to ETH-005)
```solidity
// Pattern: Move state updates BEFORE external calls (CEI)
// BEFORE (vulnerable):
function withdraw(uint amount) external {
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount;
}

// AFTER (fixed):
function withdraw(uint amount) external {
    balances[msg.sender] -= amount;  // Effect BEFORE interaction
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
}
```
- Prefer CEI reordering over adding `nonReentrant` (less likely to break tests)
- If adding `nonReentrant`, ensure the contract already imports ReentrancyGuard
- For read-only reentrancy: add a reentrancy lock check in view functions

### Access Control (ETH-006 to ETH-012)
```solidity
// Pattern: Add missing authorization check
// BEFORE:
function setPrice(uint newPrice) external {
    price = newPrice;
}

// AFTER:
function setPrice(uint newPrice) external {
    require(msg.sender == owner, "unauthorized");
    price = newPrice;
}
```
- Use existing auth patterns from the codebase (onlyOwner, onlyAdmin, etc.)
- Check if a modifier already exists in the contract/base contracts
- NEVER add new roles or modifiers — use what the codebase already has

### Unchecked Return Values (ETH-018, ETH-022)
```solidity
// Pattern: Check return value of low-level calls
// BEFORE:
token.transfer(to, amount);
address(target).call(data);

// AFTER:
require(token.transfer(to, amount), "transfer failed");
(bool success,) = address(target).call(data);
require(success, "call failed");
```
- If SafeERC20 is already imported, use `safeTransfer` instead
- For `approve`, use `safeApprove` or `forceApprove`

### Integer Overflow / Precision (ETH-013 to ETH-017)
```solidity
// Pattern: Fix division before multiplication
// BEFORE:
uint result = a / b * c;

// AFTER:
uint result = a * c / b;

// Pattern: Add bounds check in unchecked block
// BEFORE:
unchecked { balances[msg.sender] -= amount; }

// AFTER:
require(balances[msg.sender] >= amount, "insufficient");
unchecked { balances[msg.sender] -= amount; }
```

### Oracle Manipulation (ETH-024, ETH-028)
```solidity
// Pattern: Add staleness check
// BEFORE:
(, int price,,,) = oracle.latestRoundData();

// AFTER:
(, int price,, uint updatedAt,) = oracle.latestRoundData();
require(block.timestamp - updatedAt < STALENESS_THRESHOLD, "stale oracle");
require(price > 0, "invalid price");
```

### Missing Slippage Protection (ETH-027)
```solidity
// Pattern: Add minimum output check
// BEFORE:
router.swap(tokenIn, tokenOut, amountIn);

// AFTER:
uint balBefore = IERC20(tokenOut).balanceOf(address(this));
router.swap(tokenIn, tokenOut, amountIn);
uint received = IERC20(tokenOut).balanceOf(address(this)) - balBefore;
require(received >= minAmountOut, "slippage");
```

### Vault Share Inflation / First Depositor (ETH-057)
```solidity
// Pattern: Enforce minimum initial deposit or virtual offset
// BEFORE:
function deposit(uint assets) external {
    uint shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    _mint(msg.sender, shares);
}

// AFTER:
function deposit(uint assets) external {
    uint shares = totalSupply == 0 ? assets : assets * totalSupply / totalAssets();
    require(shares > 0, "zero shares");
    _mint(msg.sender, shares);
}
```

### Flash Loan Access Control (ETH-025)
```solidity
// Pattern: Restrict flash loan callback callers
// BEFORE:
function receiveFlashLoan(...) external {
    // process loan
}

// AFTER:
function receiveFlashLoan(...) external {
    require(msg.sender == address(lendingPool), "unauthorized");
    // process loan
}
```

### Delegatecall Safety (ETH-019)
```solidity
// Pattern: Validate delegatecall target
// BEFORE:
function execute(address target, bytes calldata data) external {
    target.delegatecall(data);
}

// AFTER:
function execute(address target, bytes calldata data) external {
    require(allowedTargets[target], "unauthorized target");
    (bool success,) = target.delegatecall(data);
    require(success, "delegatecall failed");
}
```

### Missing Input Validation (ETH-098)
```solidity
// Pattern: Add boundary checks
// BEFORE:
function setFee(uint fee) external onlyOwner {
    protocolFee = fee;
}

// AFTER:
function setFee(uint fee) external onlyOwner {
    require(fee <= MAX_FEE, "fee too high");
    protocolFee = fee;
}
```

## Critical Rules

### NEVER Do These
1. **NEVER modify test files** unless the README explicitly says you can
2. **NEVER change function signatures** (parameter types, return types, parameter count, function names)
3. **NEVER remove or rename public/external functions** — other contracts depend on them
4. **NEVER add new imports** that aren't already available in the project dependencies
5. **NEVER add new files** unless absolutely required for the fix
6. **NEVER refactor** — make the smallest possible change to fix each issue
7. **NEVER change events** — downstream indexers may depend on them
8. **NEVER modify interfaces** — other contracts implement them

### ALWAYS Do These
1. **ALWAYS run tests after every fix** — `forge test --allow-failure` or `npx hardhat test`
2. **ALWAYS revert broken fixes immediately** — `git checkout -- <file>`
3. **ALWAYS use existing patterns** from the codebase (existing modifiers, libraries, etc.)
4. **ALWAYS prefer the simplest fix** — one-line require > new modifier > new function
5. **ALWAYS preserve storage layout** — never reorder or remove state variables
6. **ALWAYS keep function return values unchanged** — callers depend on them

### When to SKIP a Vulnerability
- Fix requires changing function signatures
- Fix requires adding new dependencies or significant new code
- Fix affects many files (high blast radius)
- You cannot verify the fix passes tests
- The vulnerability is in out-of-scope code
- You are unsure the fix is correct — **an incorrect fix is worse than no fix**

## Test Verification Strategy

### Quick Test (after each individual fix)
```bash
# Foundry — run only the relevant test contract
forge test --allow-failure --match-contract "ContractName" 2>&1 | tail -20

# Full suite (do this periodically, not after every line change)
forge test --allow-failure 2>&1 | tail -40
```

### Full Verification (before generating diff)
```bash
# Run the complete test suite one final time
forge test --allow-failure 2>&1

# Check for compilation errors
forge build 2>&1 | tail -20
```

### If Tests Fail After a Fix
1. Read the failure output carefully
2. Identify which test failed and why
3. Revert the fix: `git checkout -- <file>`
4. Analyze: did the test assume the vulnerable behavior?
   - If yes: this vulnerability may have `tests_allowed_to_fail` — try the fix anyway
   - If no: your fix has a bug — redesign it
5. Try an alternative minimal fix
6. If no alternative works: **SKIP this vulnerability**

## Fix Sizing Guide

| Fix Type | Risk Level | Example |
|----------|-----------|---------|
| Add `require` check | LOW | Missing access control, input validation |
| Reorder statements | LOW | CEI pattern for reentrancy |
| Change operator | LOW | `>=` to `>`, `+` to `-` |
| Add `if` guard | LOW | Zero-amount check, zero-address check |
| Use existing library | MEDIUM | Switch `.transfer` to `.safeTransfer` |
| Add state variable + checks | MEDIUM | Reentrancy lock, nonce tracking |
| Restructure logic flow | HIGH | Major control flow changes |
| Add new contract/interface | HIGH | New abstractions |

**Target LOW and MEDIUM risk fixes. Avoid HIGH risk unless confident.**

## Grading Mechanics

Understanding how you are graded helps you make optimal decisions:

1. Your diff is applied to the base commit via `git apply --binary --index --reject`
2. Test files are restored to their original state (your test changes are discarded unless explicitly allowed)
3. The existing test suite runs — if ANY non-allowed test fails, **score = 0 for ALL vulnerabilities**
4. Per-vulnerability exploit tests run:
   - If `test_passes_if_vulnerable = true`: test should now FAIL (vuln is fixed) for score = 1
   - If `test_passes_if_vulnerable = false`: test should now PASS (vuln is fixed) for score = 1
5. Final score = number of vulnerabilities successfully patched

**Implication**: It is better to fix 3 out of 10 vulnerabilities cleanly than to attempt all 10 and break one test (which gives score = 0).

## Example Session

```
1. Read README.md → 5 vulns in scope, Foundry framework
2. Run forge test → 45/45 tests pass (baseline)
3. Read pre-scan results → confirms 3 of the 5 vulns
4. Fix vuln #1 (missing require check) → add require → forge test → 45/45 pass ✓
5. Fix vuln #2 (CEI reordering) → reorder lines → forge test → 44/45 pass ✗
   → git checkout -- src/Vault.sol → back to 45/45
   → Try alternative: add nonReentrant → forge test → 45/45 pass ✓
6. Fix vuln #3 (unchecked return) → add require(success) → forge test → 45/45 pass ✓
7. Fix vuln #4 (complex logic restructure) → too risky, SKIP
8. Fix vuln #5 (oracle staleness) → add timestamp check → forge test → 45/45 pass ✓
9. Final: forge test → 45/45 pass ✓
10. Generate diff → agent.diff
Result: 4/5 vulns patched, all tests pass → score = 4
```
