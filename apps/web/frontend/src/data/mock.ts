import type { Finding, RecentAudit, VulnPattern, ToolInfo, AuditStatus } from '../lib/types';

export const MOCK_FINDINGS: Finding[] = [
  {
    id: 'ETH-001',
    title: 'Single-function Reentrancy',
    severity: 'CRITICAL',
    confidence: 0.95,
    file: 'contracts/Vault.sol',
    line: 45,
    code_snippet: `function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient");
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
    balances[msg.sender] -= amount; // state update after external call
}`,
    description: 'The withdraw function sends ETH via a low-level call before updating the sender\'s balance. An attacker can re-enter the function before the balance is decremented, draining the contract.',
    attack_scenario: '1. Attacker deploys a malicious contract with a receive() function that calls withdraw() again.\n2. Attacker calls withdraw() with their full balance.\n3. The external call triggers receive(), which re-enters withdraw().\n4. Since balances[msg.sender] has not been updated yet, the check passes again.\n5. This loop repeats until the contract is drained.',
    remediation: `function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "Insufficient");
    balances[msg.sender] -= amount; // update state BEFORE external call
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok, "Transfer failed");
}`,
    category: 'Reentrancy',
    swc: 'SWC-107',
  },
  {
    id: 'ETH-019',
    title: 'Delegatecall to Untrusted Callee',
    severity: 'CRITICAL',
    confidence: 0.90,
    file: 'contracts/Proxy.sol',
    line: 23,
    code_snippet: `function forward(address target, bytes calldata data) external {
    (bool success, ) = target.delegatecall(data);
    require(success, "Delegatecall failed");
}`,
    description: 'The forward function performs a delegatecall to a user-supplied address. An attacker can provide a malicious contract that modifies the proxy\'s storage, including the admin slot.',
    attack_scenario: '1. Attacker deploys a contract with a function that writes to storage slot 0.\n2. Attacker calls forward() with the malicious contract address.\n3. The delegatecall executes in the proxy\'s context, overwriting the admin address.\n4. Attacker is now the admin and can drain all funds.',
    remediation: `// Only allow delegatecall to whitelisted implementations
mapping(address => bool) public allowedTargets;

function forward(address target, bytes calldata data) external onlyOwner {
    require(allowedTargets[target], "Target not allowed");
    (bool success, ) = target.delegatecall(data);
    require(success, "Delegatecall failed");
}`,
    category: 'External Calls',
    swc: 'SWC-112',
  },
  {
    id: 'ETH-024',
    title: 'Oracle Manipulation',
    severity: 'HIGH',
    confidence: 0.85,
    file: 'contracts/Lending.sol',
    line: 89,
    code_snippet: `function getPrice(address token) public view returns (uint256) {
    (uint112 reserve0, uint112 reserve1, ) = IUniswapV2Pair(pair).getReserves();
    return (uint256(reserve1) * 1e18) / uint256(reserve0);
}`,
    description: 'Price is derived directly from Uniswap V2 reserves which can be manipulated in a single transaction via flash loans. An attacker can temporarily skew the price to borrow more than their collateral is worth.',
    attack_scenario: '1. Attacker takes a flash loan of token0.\n2. Swaps token0 for token1 on the Uniswap pair, skewing reserves.\n3. Calls getPrice() which now returns an inflated price.\n4. Uses the inflated price to borrow against artificially valued collateral.\n5. Repays the flash loan, keeping the profit.',
    remediation: `// Use a TWAP oracle or Chainlink price feed
import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

function getPrice(address token) public view returns (uint256) {
    (, int256 price, , uint256 updatedAt, ) = priceFeed.latestRoundData();
    require(block.timestamp - updatedAt < 3600, "Stale price");
    return uint256(price);
}`,
    category: 'Oracle & Price',
    swc: null,
  },
  {
    id: 'ETH-006',
    title: 'Missing Access Control',
    severity: 'HIGH',
    confidence: 0.88,
    file: 'contracts/Vault.sol',
    line: 78,
    code_snippet: `function setFeeRecipient(address _recipient) external {
    feeRecipient = _recipient;
}`,
    description: 'The setFeeRecipient function has no access control modifier. Any user can change where fees are directed.',
    attack_scenario: '1. Attacker calls setFeeRecipient() with their own address.\n2. All future fees collected by the protocol are redirected to the attacker.\n3. No event is emitted so the change may go unnoticed.',
    remediation: `function setFeeRecipient(address _recipient) external onlyOwner {
    require(_recipient != address(0), "Zero address");
    emit FeeRecipientUpdated(feeRecipient, _recipient);
    feeRecipient = _recipient;
}`,
    category: 'Access Control',
    swc: 'SWC-105',
  },
  {
    id: 'ETH-013',
    title: 'Integer Overflow in Unchecked Block',
    severity: 'HIGH',
    confidence: 0.82,
    file: 'contracts/Token.sol',
    line: 112,
    code_snippet: `function transfer(address to, uint256 amount) external {
    unchecked {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}`,
    description: 'Arithmetic in an unchecked block bypasses Solidity 0.8+ overflow protection. If msg.sender has insufficient balance, the subtraction wraps to a very large number.',
    attack_scenario: '1. Attacker with 0 balance calls transfer(victim, 1).\n2. balances[attacker] underflows from 0 to 2^256-1.\n3. Attacker now has effectively unlimited tokens.',
    remediation: `function transfer(address to, uint256 amount) external {
    require(balances[msg.sender] >= amount, "Insufficient balance");
    unchecked {
        balances[msg.sender] -= amount;
        // overflow not possible because sum of all balances <= totalSupply
        balances[to] += amount;
    }
}`,
    category: 'Arithmetic',
    swc: 'SWC-101',
  },
  {
    id: 'ETH-057',
    title: 'Vault Share Inflation (First Depositor Attack)',
    severity: 'CRITICAL',
    confidence: 0.92,
    file: 'contracts/Vault.sol',
    line: 34,
    code_snippet: `function deposit(uint256 assets) external returns (uint256 shares) {
    shares = totalSupply == 0
        ? assets
        : (assets * totalSupply) / totalAssets();
    _mint(msg.sender, shares);
    token.transferFrom(msg.sender, address(this), assets);
}`,
    description: 'The first depositor can manipulate the share price by donating tokens directly to the vault contract, causing subsequent depositors to receive 0 shares due to rounding.',
    attack_scenario: '1. Attacker deposits 1 wei to get 1 share.\n2. Attacker donates 1e18 tokens directly to the vault.\n3. Next depositor tries to deposit 1e18 tokens.\n4. shares = (1e18 * 1) / (1e18 + 1) = 0 due to rounding.\n5. Depositor gets 0 shares; attacker redeems their 1 share for 2e18.',
    remediation: `function deposit(uint256 assets) external returns (uint256 shares) {
    shares = totalSupply == 0
        ? assets - MINIMUM_SHARES  // lock some shares to dead address
        : (assets * totalSupply) / totalAssets();
    require(shares > 0, "Zero shares");
    if (totalSupply == 0) _mint(address(0xdead), MINIMUM_SHARES);
    _mint(msg.sender, shares);
    token.transferFrom(msg.sender, address(this), assets);
}`,
    category: 'DeFi',
    swc: null,
  },
  {
    id: 'ETH-066',
    title: 'Unbounded Loop / Array Growth',
    severity: 'MEDIUM',
    confidence: 0.78,
    file: 'contracts/Registry.sol',
    line: 56,
    code_snippet: `function processAll() external {
    for (uint i = 0; i < users.length; i++) {
        _processUser(users[i]);
    }
}`,
    description: 'The function iterates over an unbounded array. As the array grows, the gas cost increases and will eventually exceed the block gas limit, making the function uncallable.',
    attack_scenario: '1. The users array grows over time as new users are added.\n2. After enough users, processAll() exceeds the block gas limit.\n3. The function becomes permanently unusable, locking any dependent functionality.',
    remediation: `function processBatch(uint256 start, uint256 count) external {
    uint256 end = start + count;
    if (end > users.length) end = users.length;
    for (uint256 i = start; i < end; i++) {
        _processUser(users[i]);
    }
}`,
    category: 'Gas & DoS',
    swc: 'SWC-128',
  },
  {
    id: 'ETH-045',
    title: 'Missing Zero Address Check',
    severity: 'LOW',
    confidence: 0.75,
    file: 'contracts/Token.sol',
    line: 28,
    code_snippet: `constructor(address _admin) {
    admin = _admin;
}`,
    description: 'The constructor does not validate that _admin is not the zero address. If deployed with address(0), admin functions become permanently inaccessible.',
    attack_scenario: '1. Contract is deployed with _admin = address(0) due to a deployment script error.\n2. All onlyAdmin functions become uncallable.\n3. Contract is permanently locked without admin capabilities.',
    remediation: `constructor(address _admin) {
    require(_admin != address(0), "Zero address");
    admin = _admin;
}`,
    category: 'Token Issues',
    swc: null,
  },
  {
    id: 'ETH-071',
    title: 'Floating Pragma',
    severity: 'INFO',
    confidence: 0.95,
    file: 'contracts/Utils.sol',
    line: 1,
    code_snippet: `pragma solidity ^0.8.0;`,
    description: 'Contracts should be deployed with the same compiler version they were tested with. A floating pragma allows compilation with any compatible version, which may introduce bugs from untested compiler versions.',
    attack_scenario: 'N/A - Best practice recommendation.',
    remediation: `pragma solidity 0.8.20;`,
    category: 'Miscellaneous',
    swc: 'SWC-103',
  },
  {
    id: 'ETH-076',
    title: 'Missing Event Emission',
    severity: 'INFO',
    confidence: 0.80,
    file: 'contracts/Vault.sol',
    line: 78,
    code_snippet: `function setFeeRecipient(address _recipient) external onlyOwner {
    feeRecipient = _recipient;
}`,
    description: 'State-changing function does not emit an event. Off-chain monitoring tools and indexers cannot track this change.',
    attack_scenario: 'N/A - Best practice for transparency and monitoring.',
    remediation: `event FeeRecipientUpdated(address indexed oldRecipient, address indexed newRecipient);

function setFeeRecipient(address _recipient) external onlyOwner {
    emit FeeRecipientUpdated(feeRecipient, _recipient);
    feeRecipient = _recipient;
}`,
    category: 'Miscellaneous',
    swc: null,
  },
];

export const MOCK_RECENT_AUDITS: RecentAudit[] = [
  { id: 'a1b2c3', name: 'MyVault.sol', score: 35, critical_count: 3, high_count: 5, files_count: 5, timestamp: '2026-02-10T08:30:00Z' },
  { id: 'd4e5f6', name: 'Token.sol', score: 82, critical_count: 0, high_count: 1, files_count: 2, timestamp: '2026-02-09T14:20:00Z' },
  { id: 'g7h8i9', name: 'Bridge.sol', score: 61, critical_count: 1, high_count: 3, files_count: 8, timestamp: '2026-02-07T09:15:00Z' },
  { id: 'j0k1l2', name: 'LendingPool.sol', score: 44, critical_count: 2, high_count: 4, files_count: 12, timestamp: '2026-02-05T16:45:00Z' },
];

export const MOCK_AUDIT_STATUS: AuditStatus = {
  id: 'a1b2c3',
  status: 'running',
  phase: 3,
  total_phases: 7,
  phase_name: 'Pattern Analysis',
  progress: 0.56,
  findings_count: { CRITICAL: 3, HIGH: 3, MEDIUM: 1, LOW: 1, INFO: 2 },
  started_at: '2026-02-10T08:30:00Z',
  completed_at: null,
};

export const MOCK_TOOLS: ToolInfo[] = [
  { name: 'pattern', status: 'done', label: 'Pattern Scanner' },
  { name: 'slither', status: 'done', label: 'Slither' },
  { name: 'aderyn', status: 'running', label: 'Aderyn' },
  { name: 'mythril', status: 'error', label: 'Mythril' },
  { name: 'echidna', status: 'idle', label: 'Echidna' },
  { name: 'foundry', status: 'idle', label: 'Foundry' },
  { name: 'halmos', status: 'unavailable', label: 'Halmos' },
  { name: 'certora', status: 'unavailable', label: 'Certora' },
];

export const MOCK_FILES = [
  'contracts/Vault.sol',
  'contracts/Proxy.sol',
  'contracts/Lending.sol',
  'contracts/Token.sol',
  'contracts/Registry.sol',
  'contracts/Utils.sol',
];

export const MOCK_PATTERNS: VulnPattern[] = [
  { id: 'ETH-001', name: 'Single-function Reentrancy', severity: 'CRITICAL', category: 'Reentrancy', description: 'A function makes an external call before updating state, allowing recursive re-entry.', swc: 'SWC-107' },
  { id: 'ETH-002', name: 'Cross-function Reentrancy', severity: 'CRITICAL', category: 'Reentrancy', description: 'Reentrancy across two functions that share state, where one calls externally and the other reads stale state.', swc: 'SWC-107' },
  { id: 'ETH-003', name: 'Cross-contract Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Reentrancy exploiting shared state across multiple contracts.', swc: 'SWC-107' },
  { id: 'ETH-004', name: 'Read-only Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Re-entering a view function during execution to read stale state used by another protocol.', swc: null },
  { id: 'ETH-005', name: 'Cross-chain Reentrancy', severity: 'HIGH', category: 'Reentrancy', description: 'Reentrancy exploiting cross-chain message passing where state is not finalized.', swc: null },
  { id: 'ETH-006', name: 'Missing Access Control', severity: 'CRITICAL', category: 'Access Control', description: 'Privileged function lacks access control modifier, allowing anyone to call it.', swc: 'SWC-105' },
  { id: 'ETH-007', name: 'tx.origin Authentication', severity: 'CRITICAL', category: 'Access Control', description: 'Using tx.origin for authentication enables phishing attacks through intermediate contracts.', swc: 'SWC-115' },
  { id: 'ETH-008', name: 'Unprotected selfdestruct', severity: 'CRITICAL', category: 'Access Control', description: 'selfdestruct callable without proper access control can destroy the contract.', swc: 'SWC-106' },
  { id: 'ETH-009', name: 'Default Function Visibility', severity: 'HIGH', category: 'Access Control', description: 'Functions without explicit visibility default to public in older Solidity versions.', swc: 'SWC-100' },
  { id: 'ETH-010', name: 'Uninitialized Proxy', severity: 'CRITICAL', category: 'Access Control', description: 'Proxy contract not initialized, allowing attacker to call initialize() and take ownership.', swc: null },
  { id: 'ETH-011', name: 'Missing Modifier on State-changing Function', severity: 'HIGH', category: 'Access Control', description: 'Function that changes critical state lacks an access modifier.', swc: null },
  { id: 'ETH-012', name: 'Centralization Risk / Single Admin', severity: 'MEDIUM', category: 'Access Control', description: 'Single admin key controls critical functions without timelock or multisig.', swc: null },
  { id: 'ETH-013', name: 'Integer Overflow/Underflow', severity: 'HIGH', category: 'Arithmetic', description: 'Arithmetic operation overflows or underflows, especially in unchecked blocks.', swc: 'SWC-101' },
  { id: 'ETH-014', name: 'Division Before Multiplication', severity: 'MEDIUM', category: 'Arithmetic', description: 'Division before multiplication causes precision loss due to integer truncation.', swc: null },
  { id: 'ETH-015', name: 'Unchecked Math in unchecked Block', severity: 'HIGH', category: 'Arithmetic', description: 'Unsafe arithmetic in Solidity 0.8+ unchecked blocks bypasses overflow protection.', swc: null },
  { id: 'ETH-016', name: 'Rounding Errors', severity: 'MEDIUM', category: 'Arithmetic', description: 'Rounding in token/share calculations can be exploited for profit.', swc: null },
  { id: 'ETH-017', name: 'Precision Loss in Token Calculations', severity: 'MEDIUM', category: 'Arithmetic', description: 'Loss of precision when converting between tokens with different decimals.', swc: null },
  { id: 'ETH-018', name: 'Unchecked External Call Return', severity: 'HIGH', category: 'External Calls', description: 'Return value of external call not checked, silently ignoring failures.', swc: 'SWC-104' },
  { id: 'ETH-019', name: 'Delegatecall to Untrusted Callee', severity: 'CRITICAL', category: 'External Calls', description: 'delegatecall to user-supplied address allows arbitrary storage modification.', swc: 'SWC-112' },
  { id: 'ETH-020', name: 'Unsafe Low-level Call', severity: 'HIGH', category: 'External Calls', description: 'Raw call/staticcall without proper validation and return checking.', swc: null },
  { id: 'ETH-021', name: 'DoS with Failed Call', severity: 'HIGH', category: 'External Calls', description: 'Failed external call in a loop blocks all subsequent operations.', swc: 'SWC-113' },
  { id: 'ETH-022', name: 'Return Value Not Checked (ERC-20)', severity: 'HIGH', category: 'External Calls', description: 'ERC-20 transfer/approve return values not checked, ignoring transfer failures.', swc: null },
  { id: 'ETH-023', name: 'Insufficient Gas Griefing', severity: 'MEDIUM', category: 'External Calls', description: 'External call forwarded with insufficient gas causing subtle failures.', swc: 'SWC-126' },
  { id: 'ETH-024', name: 'Oracle Manipulation', severity: 'CRITICAL', category: 'Oracle & Price', description: 'Price oracle can be manipulated in a single transaction.', swc: null },
  { id: 'ETH-025', name: 'Flash Loan Attack Vector', severity: 'CRITICAL', category: 'Oracle & Price', description: 'Protocol vulnerable to flash loan-funded price manipulation.', swc: null },
  { id: 'ETH-026', name: 'Sandwich Attack / MEV', severity: 'HIGH', category: 'Oracle & Price', description: 'Transactions can be sandwiched by MEV bots for profit extraction.', swc: null },
  { id: 'ETH-027', name: 'Missing Slippage Protection', severity: 'HIGH', category: 'Oracle & Price', description: 'Swap or trade without slippage limit allows unfavorable execution.', swc: null },
  { id: 'ETH-028', name: 'Stale Oracle Data', severity: 'HIGH', category: 'Oracle & Price', description: 'Oracle price data not checked for freshness, using potentially stale prices.', swc: null },
  { id: 'ETH-029', name: 'Uninitialized Storage Pointer', severity: 'HIGH', category: 'Storage & State', description: 'Local storage variable not initialized points to slot 0.', swc: 'SWC-109' },
  { id: 'ETH-030', name: 'Storage Collision (Proxy)', severity: 'CRITICAL', category: 'Storage & State', description: 'Proxy and implementation storage layouts collide, corrupting data.', swc: 'SWC-124' },
  { id: 'ETH-031', name: 'Shadowing State Variables', severity: 'MEDIUM', category: 'Storage & State', description: 'Child contract variable shadows parent, causing unexpected behavior.', swc: 'SWC-119' },
  { id: 'ETH-032', name: 'Unexpected Ether Balance', severity: 'MEDIUM', category: 'Storage & State', description: 'Contract logic depends on this.balance which can be manipulated via selfdestruct.', swc: 'SWC-132' },
  { id: 'ETH-033', name: 'Write to Arbitrary Storage Location', severity: 'CRITICAL', category: 'Storage & State', description: 'User input controls storage slot being written to.', swc: 'SWC-124' },
  { id: 'ETH-034', name: 'Strict Equality on Balance', severity: 'HIGH', category: 'Logic Errors', description: 'Using == to check ETH balance can be broken by forced ETH sends.', swc: 'SWC-132' },
  { id: 'ETH-035', name: 'Transaction Order Dependence', severity: 'HIGH', category: 'Logic Errors', description: 'Contract behavior depends on transaction ordering (front-running).', swc: 'SWC-114' },
  { id: 'ETH-036', name: 'Timestamp Dependence', severity: 'MEDIUM', category: 'Logic Errors', description: 'Using block.timestamp for critical logic, manipulable by miners.', swc: 'SWC-116' },
  { id: 'ETH-037', name: 'Weak Randomness', severity: 'HIGH', category: 'Logic Errors', description: 'Using blockhash/timestamp for randomness is predictable by miners.', swc: 'SWC-120' },
  { id: 'ETH-038', name: 'Signature Malleability', severity: 'HIGH', category: 'Logic Errors', description: 'ECDSA signatures are malleable; both (v,r,s) and (v\',r,s\') are valid.', swc: 'SWC-117' },
  { id: 'ETH-039', name: 'Signature Replay Attack', severity: 'CRITICAL', category: 'Logic Errors', description: 'Signed message can be replayed across chains or contracts without nonce.', swc: 'SWC-121' },
  { id: 'ETH-040', name: 'Front-running Vulnerability', severity: 'HIGH', category: 'Logic Errors', description: 'Transaction can be observed in mempool and front-run for profit.', swc: 'SWC-114' },
  { id: 'ETH-041', name: 'ERC-20 Non-standard Return Values', severity: 'HIGH', category: 'Token Issues', description: 'Some ERC-20 tokens don\'t return bool on transfer, causing reverts.', swc: null },
  { id: 'ETH-042', name: 'Fee-on-Transfer Token Incompatibility', severity: 'HIGH', category: 'Token Issues', description: 'Protocol assumes transferred amount equals parameter, broken by fee tokens.', swc: null },
  { id: 'ETH-043', name: 'Rebasing Token Incompatibility', severity: 'HIGH', category: 'Token Issues', description: 'Protocol caches token balances, broken by rebasing tokens.', swc: null },
  { id: 'ETH-044', name: 'ERC-777 Reentrancy Hook', severity: 'CRITICAL', category: 'Token Issues', description: 'ERC-777 tokens call hooks on transfer, enabling reentrancy.', swc: null },
  { id: 'ETH-045', name: 'Missing Zero Address Check', severity: 'MEDIUM', category: 'Token Issues', description: 'Critical address parameter not checked for zero address.', swc: null },
  { id: 'ETH-046', name: 'Approval Race Condition', severity: 'MEDIUM', category: 'Token Issues', description: 'ERC-20 approve race condition allows double-spending.', swc: null },
  { id: 'ETH-047', name: 'Infinite Approval Risk', severity: 'LOW', category: 'Token Issues', description: 'Contracts requesting max approval expose users to full loss if compromised.', swc: null },
  { id: 'ETH-048', name: 'Token Supply Manipulation', severity: 'HIGH', category: 'Token Issues', description: 'Mint/burn functions allow unauthorized token supply changes.', swc: null },
  { id: 'ETH-049', name: 'Uninitialized Implementation Contract', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'Implementation contract not initialized, allowing takeover.', swc: null },
  { id: 'ETH-050', name: 'Storage Layout Mismatch on Upgrade', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'New implementation has different storage layout, corrupting state.', swc: null },
  { id: 'ETH-051', name: 'Function Selector Clash', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'Proxy and implementation have functions with same selector.', swc: null },
  { id: 'ETH-052', name: 'Missing Upgrade Authorization', severity: 'CRITICAL', category: 'Proxy & Upgrade', description: 'upgradeTo function lacks access control, allowing malicious upgrades.', swc: null },
  { id: 'ETH-053', name: 'selfdestruct in Implementation', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'selfdestruct in implementation can destroy the proxy\'s code.', swc: null },
  { id: 'ETH-054', name: 'Transparent Proxy Selector Collision', severity: 'HIGH', category: 'Proxy & Upgrade', description: 'Admin functions collide with implementation selectors.', swc: null },
  { id: 'ETH-055', name: 'Governance Manipulation', severity: 'HIGH', category: 'DeFi', description: 'Governance voting can be manipulated via flash loans or vote buying.', swc: null },
  { id: 'ETH-056', name: 'Liquidation Manipulation', severity: 'HIGH', category: 'DeFi', description: 'Liquidation mechanism can be gamed for profit.', swc: null },
  { id: 'ETH-057', name: 'Vault Share Inflation / First Depositor', severity: 'CRITICAL', category: 'DeFi', description: 'First depositor can manipulate share price to steal from later depositors.', swc: null },
  { id: 'ETH-058', name: 'Donation Attack', severity: 'HIGH', category: 'DeFi', description: 'Direct token transfer skews share/price calculations.', swc: null },
  { id: 'ETH-059', name: 'AMM Constant Product Error', severity: 'CRITICAL', category: 'DeFi', description: 'AMM invariant not properly enforced, allowing value extraction.', swc: null },
  { id: 'ETH-060', name: 'Missing Transaction Deadline', severity: 'MEDIUM', category: 'DeFi', description: 'Swap transaction without deadline can be held and executed at unfavorable price.', swc: null },
  { id: 'ETH-061', name: 'Unrestricted Flash Mint', severity: 'HIGH', category: 'DeFi', description: 'Flash mint without proper controls allows infinite temporary token creation.', swc: null },
  { id: 'ETH-062', name: 'Pool Imbalance Attack', severity: 'HIGH', category: 'DeFi', description: 'Attacker intentionally imbalances a pool to extract value.', swc: null },
  { id: 'ETH-063', name: 'Reward Distribution Error', severity: 'HIGH', category: 'DeFi', description: 'Reward calculation error allows over-claiming or excludes eligible users.', swc: null },
  { id: 'ETH-064', name: 'Insecure Callback / Hook Handler', severity: 'HIGH', category: 'DeFi', description: 'Callback from external protocol not properly validated.', swc: null },
  { id: 'ETH-065', name: 'Cross-protocol Integration Risk', severity: 'MEDIUM', category: 'DeFi', description: 'Composability risk from integrating with external protocols.', swc: null },
  { id: 'ETH-066', name: 'Unbounded Loop / Array Growth', severity: 'HIGH', category: 'Gas & DoS', description: 'Loop iterates over unbounded array that can grow beyond gas limits.', swc: 'SWC-128' },
  { id: 'ETH-067', name: 'Block Gas Limit DoS', severity: 'HIGH', category: 'Gas & DoS', description: 'Function exceeds block gas limit, becoming permanently uncallable.', swc: 'SWC-128' },
  { id: 'ETH-068', name: 'Unexpected Revert in Loop', severity: 'MEDIUM', category: 'Gas & DoS', description: 'Single revert in loop blocks processing of all remaining items.', swc: 'SWC-113' },
  { id: 'ETH-069', name: 'Griefing Attack', severity: 'MEDIUM', category: 'Gas & DoS', description: 'Attacker can waste victim\'s gas or block their transactions.', swc: null },
  { id: 'ETH-070', name: 'Storage Slot Exhaustion', severity: 'LOW', category: 'Gas & DoS', description: 'Attacker fills storage slots, increasing gas costs for the contract.', swc: null },
  { id: 'ETH-071', name: 'Floating Pragma', severity: 'LOW', category: 'Miscellaneous', description: 'Pragma not locked to specific compiler version.', swc: 'SWC-103' },
  { id: 'ETH-072', name: 'Outdated Compiler Version', severity: 'LOW', category: 'Miscellaneous', description: 'Using old Solidity version with known bugs.', swc: 'SWC-102' },
  { id: 'ETH-073', name: 'Hash Collision with abi.encodePacked', severity: 'MEDIUM', category: 'Miscellaneous', description: 'abi.encodePacked with multiple dynamic types allows hash collisions.', swc: 'SWC-133' },
  { id: 'ETH-074', name: 'Right-to-Left Override Character', severity: 'HIGH', category: 'Miscellaneous', description: 'Unicode RTL override used to disguise malicious code.', swc: 'SWC-130' },
  { id: 'ETH-075', name: 'Code With No Effects', severity: 'LOW', category: 'Miscellaneous', description: 'Statement has no effect, indicating a logic error.', swc: 'SWC-135' },
  { id: 'ETH-076', name: 'Missing Event Emission', severity: 'LOW', category: 'Miscellaneous', description: 'State change without event emission hinders off-chain monitoring.', swc: null },
  { id: 'ETH-077', name: 'Incorrect Inheritance Order', severity: 'MEDIUM', category: 'Miscellaneous', description: 'C3 linearization causes unexpected function resolution.', swc: 'SWC-125' },
  { id: 'ETH-078', name: 'Unencrypted Private Data On-Chain', severity: 'LOW', category: 'Miscellaneous', description: 'Private variables readable by anyone via storage slots.', swc: 'SWC-136' },
  { id: 'ETH-079', name: 'Hardcoded Gas Amount', severity: 'LOW', category: 'Miscellaneous', description: 'Hardcoded gas in call may break after EVM gas schedule changes.', swc: 'SWC-134' },
  { id: 'ETH-080', name: 'Incorrect Constructor Name (legacy)', severity: 'HIGH', category: 'Miscellaneous', description: 'Constructor name doesn\'t match contract (pre-0.4.22).', swc: 'SWC-118' },
  { id: 'ETH-081', name: 'Transient Storage Slot Collision', severity: 'CRITICAL', category: 'Transient Storage', description: 'Multiple contracts using same transient storage slot via delegatecall.', swc: null },
  { id: 'ETH-082', name: 'Transient Storage Not Cleared', severity: 'HIGH', category: 'Transient Storage', description: 'Transient storage value persists within transaction, causing stale reads.', swc: null },
  { id: 'ETH-083', name: 'TSTORE Reentrancy Bypass', severity: 'CRITICAL', category: 'Transient Storage', description: 'Reentrancy guard using transient storage can be bypassed.', swc: null },
  { id: 'ETH-084', name: 'Transient Storage Delegatecall Exposure', severity: 'HIGH', category: 'Transient Storage', description: 'Delegatecall shares transient storage context, enabling cross-contract leaks.', swc: null },
  { id: 'ETH-085', name: 'Transient Storage Type-Safety Bypass', severity: 'MEDIUM', category: 'Transient Storage', description: 'Raw TSTORE/TLOAD bypasses Solidity type safety checks.', swc: null },
  { id: 'ETH-086', name: 'Broken tx.origin == msg.sender Assumption', severity: 'CRITICAL', category: 'EIP-7702', description: 'EIP-7702 breaks the assumption that tx.origin == msg.sender means EOA caller.', swc: null },
  { id: 'ETH-087', name: 'Malicious EIP-7702 Delegation', severity: 'HIGH', category: 'EIP-7702', description: 'EOA delegates to malicious contract that drains funds on next transaction.', swc: null },
  { id: 'ETH-088', name: 'EIP-7702 Cross-Chain Authorization Replay', severity: 'CRITICAL', category: 'EIP-7702', description: 'EIP-7702 authorization replayed on different chain.', swc: null },
  { id: 'ETH-089', name: 'EOA Code Assumption Failure', severity: 'HIGH', category: 'EIP-7702', description: 'Code assumes extcodesize(addr)==0 means EOA; broken by EIP-7702.', swc: null },
  { id: 'ETH-090', name: 'UserOp Hash Collision', severity: 'HIGH', category: 'Account Abstraction', description: 'ERC-4337 UserOperation hash collision allows operation replay.', swc: null },
  { id: 'ETH-091', name: 'Paymaster Exploitation', severity: 'CRITICAL', category: 'Account Abstraction', description: 'Paymaster can be drained by crafted UserOperations.', swc: null },
  { id: 'ETH-092', name: 'Bundler Manipulation', severity: 'HIGH', category: 'Account Abstraction', description: 'Malicious bundler reorders or censors UserOperations.', swc: null },
  { id: 'ETH-093', name: 'Validation-Execution Phase Confusion', severity: 'CRITICAL', category: 'Account Abstraction', description: 'Logic intended for execution phase runs during validation.', swc: null },
  { id: 'ETH-094', name: 'Uniswap V4 Hook Callback Authorization', severity: 'CRITICAL', category: 'Modern DeFi', description: 'Hook callback not properly authorized, allowing arbitrary callers.', swc: null },
  { id: 'ETH-095', name: 'Hook Data Manipulation', severity: 'HIGH', category: 'Modern DeFi', description: 'Hook data parameters not validated, allowing injection attacks.', swc: null },
  { id: 'ETH-096', name: 'Cached State Desynchronization', severity: 'HIGH', category: 'Modern DeFi', description: 'Cached protocol state diverges from actual state, enabling exploits.', swc: null },
  { id: 'ETH-097', name: 'Known Compiler Bug in Used Version', severity: 'HIGH', category: 'Modern DeFi', description: 'Solidity version has known bugs that may affect contract behavior.', swc: null },
  { id: 'ETH-098', name: 'Missing Input Validation / Boundary Check', severity: 'HIGH', category: 'Input Validation', description: 'Function parameters not validated for bounds, allowing extreme values.', swc: null },
  { id: 'ETH-099', name: 'Unsafe ABI Decoding / Calldata Manipulation', severity: 'HIGH', category: 'Input Validation', description: 'ABI decoding of untrusted calldata without validation.', swc: null },
  { id: 'ETH-100', name: 'EIP-7702 Delegation Phishing', severity: 'CRITICAL', category: 'Off-Chain', description: 'User tricked into signing EIP-7702 delegation to malicious contract.', swc: null },
  { id: 'ETH-101', name: 'Off-Chain Infrastructure Compromise', severity: 'CRITICAL', category: 'Off-Chain', description: 'UI/frontend/signer infrastructure compromised (Bybit pattern).', swc: null },
  { id: 'ETH-102', name: 'Restaking Cascading Slashing Risk', severity: 'HIGH', category: 'Restaking & L2', description: 'Cascading slashing across restaking protocols amplifies losses.', swc: null },
  { id: 'ETH-103', name: 'L2 Sequencer Dependency', severity: 'HIGH', category: 'Restaking & L2', description: 'Protocol depends on L2 sequencer uptime for critical operations.', swc: null },
  { id: 'ETH-104', name: 'L2 Cross-Domain Message Replay', severity: 'CRITICAL', category: 'Restaking & L2', description: 'Cross-domain message replayed on different L2 or after reorg.', swc: null },
];

export const MOCK_REPORT_MD = `# Security Audit Report

## SolidityGuard Automated Audit

**Target**: contracts/ (6 files, 847 lines)
**Date**: February 10, 2026
**Tools**: Pattern Scanner, Slither, Aderyn

---

## Executive Summary

The audit identified **10 findings** across 6 contracts:
- **3 Critical** severity issues requiring immediate attention
- **3 High** severity issues
- **1 Medium** severity issue
- **1 Low** severity issue
- **2 Informational** findings

**Security Score: 35/100** (Poor)

The most critical findings involve reentrancy vulnerabilities in the Vault contract and delegatecall misuse in the Proxy contract. These should be addressed before deployment.

---

## Findings Summary

| # | ID | Title | Severity | Confidence | File |
|---|-----|-------|----------|------------|------|
| 1 | ETH-001 | Single-function Reentrancy | CRITICAL | 95% | Vault.sol:45 |
| 2 | ETH-019 | Delegatecall to Untrusted Callee | CRITICAL | 90% | Proxy.sol:23 |
| 3 | ETH-057 | Vault Share Inflation | CRITICAL | 92% | Vault.sol:34 |
| 4 | ETH-024 | Oracle Manipulation | HIGH | 85% | Lending.sol:89 |
| 5 | ETH-006 | Missing Access Control | HIGH | 88% | Vault.sol:78 |
| 6 | ETH-013 | Integer Overflow in Unchecked | HIGH | 82% | Token.sol:112 |
| 7 | ETH-066 | Unbounded Loop | MEDIUM | 78% | Registry.sol:56 |
| 8 | ETH-045 | Missing Zero Address Check | LOW | 75% | Token.sol:28 |
| 9 | ETH-071 | Floating Pragma | INFO | 95% | Utils.sol:1 |
| 10 | ETH-076 | Missing Event Emission | INFO | 80% | Vault.sol:78 |

---

## Detailed Findings

### [C-01] Single-function Reentrancy (ETH-001)

**Severity**: CRITICAL | **Confidence**: 95% | **SWC**: SWC-107

**Location**: \`contracts/Vault.sol:45\`

The withdraw function sends ETH via a low-level call before updating the sender's balance, enabling recursive re-entry to drain the contract.

**Recommendation**: Apply the checks-effects-interactions pattern and use a reentrancy guard.

---

### [C-02] Delegatecall to Untrusted Callee (ETH-019)

**Severity**: CRITICAL | **Confidence**: 90% | **SWC**: SWC-112

**Location**: \`contracts/Proxy.sol:23\`

The forward function performs delegatecall to a user-supplied address, allowing arbitrary storage modification.

**Recommendation**: Whitelist allowed delegatecall targets.

---

## Tools Used

- **SolidityGuard Pattern Scanner** v1.0 — 104 vulnerability patterns
- **Slither** v0.10.4 — static analysis
- **Aderyn** v0.5.0 — Rust-based static analysis

---

*Generated by SolidityGuard v1.0*
`;
