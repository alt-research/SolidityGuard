interface CodeSnippetProps {
  code: string
  startLine?: number
  language?: 'solidity' | 'text'
}

function stripHtml(text: string): string {
  // Remove any pre-existing HTML tags from scanner output
  return text.replace(/<[^>]+>/g, '')
}

function highlightSolidity(line: string): string {
  // Escape HTML first
  let result = line
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')

  // Comments (must be first to avoid highlighting inside them)
  result = result.replace(/(\/\/.*)$/gm, '<span class="sol-comment">$1</span>')

  // Strings
  result = result.replace(/("(?:[^"\\]|\\.)*")/g, '<span class="sol-string">$1</span>')

  // Numbers
  result = result.replace(/\b(\d+(?:e\d+)?)\b/g, '<span class="sol-number">$1</span>')

  // Keywords
  const keywords = [
    'pragma', 'solidity', 'contract', 'library', 'interface', 'function', 'modifier',
    'event', 'struct', 'enum', 'mapping', 'if', 'else', 'for', 'while', 'do', 'break',
    'continue', 'return', 'returns', 'require', 'revert', 'assert', 'emit', 'new',
    'delete', 'import', 'using', 'is', 'constructor', 'fallback', 'receive', 'virtual',
    'override', 'abstract', 'try', 'catch', 'unchecked', 'assembly',
  ]
  result = result.replace(
    new RegExp(`\\b(${keywords.join('|')})\\b`, 'g'),
    '<span class="sol-keyword">$1</span>',
  )

  // Visibility / state mutability
  const modifiers = [
    'public', 'private', 'internal', 'external', 'view', 'pure', 'payable',
    'memory', 'storage', 'calldata', 'constant', 'immutable', 'indexed',
    'nonReentrant', 'onlyOwner', 'onlyAdmin',
  ]
  result = result.replace(
    new RegExp(`\\b(${modifiers.join('|')})\\b`, 'g'),
    '<span class="sol-modifier">$1</span>',
  )

  // Types
  const types = [
    'address', 'bool', 'string', 'bytes', 'uint', 'int', 'uint256', 'uint128',
    'uint112', 'uint64', 'uint32', 'uint16', 'uint8', 'int256', 'bytes32', 'bytes4',
  ]
  result = result.replace(
    new RegExp(`\\b(${types.join('|')})\\b`, 'g'),
    '<span class="sol-type">$1</span>',
  )

  return result
}

export default function CodeSnippet({ code, startLine = 1 }: CodeSnippetProps) {
  if (!code) {
    return (
      <div className="bg-[var(--theme-code-bg)] rounded-lg border border-[var(--color-border)] p-4">
        <span className="text-xs text-[var(--color-text-secondary)]">No code available</span>
      </div>
    )
  }

  // Strip any pre-existing HTML tags from scanner output
  const cleanCode = stripHtml(code)
  const lines = cleanCode.split('\n')

  return (
    <div className="bg-[var(--theme-code-bg)] rounded-lg border border-[var(--color-border)] overflow-x-auto">
      <pre className="text-sm leading-relaxed p-0 m-0">
        <code>
          {lines.map((line, i) => (
            <div key={i} className="flex hover:bg-[var(--color-surface-hover)]">
              <span className="flex-shrink-0 w-12 text-right pr-3 text-[var(--color-text-secondary)]/50 select-none font-mono text-xs leading-relaxed py-px">
                {startLine + i}
              </span>
              <span
                className="font-mono text-xs leading-relaxed py-px flex-1 pr-4"
                dangerouslySetInnerHTML={{ __html: highlightSolidity(line) }}
              />
            </div>
          ))}
        </code>
      </pre>
    </div>
  )
}
