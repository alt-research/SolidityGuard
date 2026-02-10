import { useState, useCallback } from 'react'
import { Upload, File, X } from 'lucide-react'

interface FileUploadProps {
  files: File[]
  onFilesChange: (files: File[]) => void
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

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const dropped = Array.from(e.dataTransfer.files).filter(
      (f) => f.name.endsWith('.sol') || f.name.endsWith('.vy')
    )
    onFilesChange([...files, ...dropped])
  }, [files, onFilesChange])

  const handleInputChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const selected = Array.from(e.target.files)
      onFilesChange([...files, ...selected])
    }
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
        <p className="text-[15px] text-text-primary font-medium">Drop Solidity files here</p>
        <p className="text-[13px] text-text-secondary mt-1.5">or click to browse</p>
        <p className="text-[11px] text-text-secondary mt-3 opacity-60">.sol and .vy files supported</p>
        <input
          id="file-input"
          type="file"
          multiple
          accept=".sol,.vy"
          className="hidden"
          onChange={handleInputChange}
        />
      </div>

      {files.length > 0 && (
        <div className="space-y-1.5">
          {files.map((file, i) => (
            <div
              key={`${file.name}-${i}`}
              className="flex items-center justify-between bg-surface/50 rounded-lg px-4 py-2.5 group"
            >
              <div className="flex items-center gap-2.5">
                <File className="w-4 h-4 text-accent" />
                <span className="text-[13px] text-text-primary font-medium">{file.name}</span>
                <span className="text-[11px] text-text-secondary">
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
      )}
    </div>
  )
}
