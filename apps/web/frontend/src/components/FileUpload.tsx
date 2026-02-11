import { useState, useCallback } from 'react'
import { Upload, File, X, FolderOpen } from 'lucide-react'

interface FileUploadProps {
  files: File[]
  onFilesChange: (files: File[]) => void
}

const ALLOWED_EXT = ['.sol', '.vy']

function isAllowed(name: string): boolean {
  return ALLOWED_EXT.some((ext) => name.endsWith(ext))
}

/** Recursively read all files from a dropped directory entry. */
function readEntryRecursive(entry: FileSystemEntry): Promise<File[]> {
  return new Promise((resolve) => {
    if (entry.isFile) {
      (entry as FileSystemFileEntry).file(
        (file) => resolve(isAllowed(file.name) ? [file] : []),
        () => resolve([]),
      )
    } else if (entry.isDirectory) {
      const reader = (entry as FileSystemDirectoryEntry).createReader()
      const allFiles: File[] = []

      // readEntries may return partial results — keep calling until empty
      const readBatch = () => {
        reader.readEntries(
          (entries) => {
            if (entries.length === 0) {
              resolve(allFiles)
              return
            }
            Promise.all(entries.map(readEntryRecursive)).then((nested) => {
              allFiles.push(...nested.flat())
              readBatch()
            })
          },
          () => resolve(allFiles),
        )
      }
      readBatch()
    } else {
      resolve([])
    }
  })
}

export default function FileUpload({ files, onFilesChange }: FileUploadProps) {
  const [isDragging, setIsDragging] = useState(false)

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }, [])

  const handleDragLeave = useCallback(() => {
    setIsDragging(false)
  }, [])

  const handleDrop = useCallback(async (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)

    const items = e.dataTransfer.items
    const collected: File[] = []

    if (items && items.length > 0) {
      // Use webkitGetAsEntry to support folder drops
      const entries: FileSystemEntry[] = []
      for (let i = 0; i < items.length; i++) {
        const entry = items[i].webkitGetAsEntry?.()
        if (entry) entries.push(entry)
      }

      if (entries.length > 0) {
        const nested = await Promise.all(entries.map(readEntryRecursive))
        collected.push(...nested.flat())
      } else {
        // Fallback: plain file drop (no entry API)
        const dropped = Array.from(e.dataTransfer.files).filter((f) => isAllowed(f.name))
        collected.push(...dropped)
      }
    }

    if (collected.length > 0) {
      onFilesChange([...files, ...collected])
    }
  }, [files, onFilesChange])

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selected = Array.from(e.target.files).filter((f) => isAllowed(f.name))
      onFilesChange([...files, ...selected])
    }
    e.target.value = ''
  }, [files, onFilesChange])

  const handleFolderInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selected = Array.from(e.target.files).filter((f) => isAllowed(f.name))
      onFilesChange([...files, ...selected])
    }
    e.target.value = ''
  }, [files, onFilesChange])

  const removeFile = useCallback((index: number) => {
    onFilesChange(files.filter((_, i) => i !== index))
  }, [files, onFilesChange])

  return (
    <div className="space-y-4">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        className={`border border-dashed rounded-xl p-10 text-center cursor-pointer transition-all duration-200 ${
          isDragging
            ? 'border-accent bg-accent/5 scale-[1.01]'
            : 'border-border-strong hover:border-text-secondary hover:bg-surface/30'
        }`}
        onClick={() => document.getElementById('file-input')?.click()}
      >
        <div className={`inline-flex items-center justify-center w-12 h-12 rounded-xl mb-4 ${
          isDragging ? 'bg-accent/15' : 'bg-surface'
        }`}>
          <Upload className={`w-5 h-5 ${isDragging ? 'text-accent' : 'text-text-secondary'}`} />
        </div>
        <p className="text-[15px] text-text-primary font-medium">
          Drop files or folders here
        </p>
        <p className="text-[13px] text-text-secondary mt-1.5">or click to browse files</p>
        <p className="text-[11px] text-text-secondary mt-3 opacity-60">.sol and .vy files supported</p>
        <input
          id="file-input"
          type="file"
          multiple
          accept=".sol,.vy"
          className="hidden"
          onChange={handleFileInput}
        />
        <input
          id="folder-input"
          type="file"
          // @ts-expect-error webkitdirectory is not in React's types
          webkitdirectory=""
          directory=""
          multiple
          className="hidden"
          onChange={handleFolderInput}
        />
      </div>

      <div className="flex justify-center">
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); document.getElementById('folder-input')?.click() }}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-surface/50 border border-border text-[13px] text-text-secondary hover:text-text-primary hover:border-text-secondary/30 transition-colors cursor-pointer"
        >
          <FolderOpen className="w-4 h-4" />
          Select Folder
        </button>
      </div>

      {files.length > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between px-1">
            <span className="text-[12px] text-text-secondary font-medium">
              {files.length} file{files.length !== 1 ? 's' : ''} selected
            </span>
            <button
              onClick={() => onFilesChange([])}
              className="text-[12px] text-text-secondary hover:text-severity-critical transition-colors cursor-pointer"
            >
              Clear all
            </button>
          </div>
          <div className="max-h-48 overflow-y-auto space-y-1.5">
            {files.map((file, i) => (
              <div
                key={`${file.name}-${i}`}
                className="flex items-center justify-between bg-surface/50 rounded-lg px-4 py-2.5 group"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <File className="w-4 h-4 text-accent shrink-0" />
                  <span className="text-[13px] text-text-primary font-medium truncate">
                    {file.webkitRelativePath || file.name}
                  </span>
                  <span className="text-[11px] text-text-secondary shrink-0">
                    {(file.size / 1024).toFixed(1)} KB
                  </span>
                </div>
                <button
                  onClick={(e) => { e.stopPropagation(); removeFile(i) }}
                  className="text-text-secondary hover:text-severity-critical transition-colors opacity-0 group-hover:opacity-100 cursor-pointer"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
