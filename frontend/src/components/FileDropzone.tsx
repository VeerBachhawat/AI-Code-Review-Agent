import React, { useState, useRef } from 'react';
import { Upload, FileCode, CheckCircle2, AlertCircle } from 'lucide-react';
import { apiService } from '../services/api';

interface FileDropzoneProps {
  onFileLoaded: (code: string, filename: string, language: string) => void;
  currentFilename: string;
  detectedLanguage: string;
  hasCode: boolean;
}

const SUPPORTED_EXTENSIONS = ['.py', '.java', '.cpp', '.cc', '.cxx', '.c', '.js', '.jsx', '.ts', '.tsx', '.txt'];

export const FileDropzone: React.FC<FileDropzoneProps> = ({
  onFileLoaded,
  currentFilename,
  detectedLanguage,
  hasCode,
}) => {
  const [isDragOver, setIsDragOver] = useState(false);
  const [errorMsg, setErrorMsg] = useState('');
  const fileInputRef = useRef<HTMLInputElement>(null);

  const detectLanguageFromExtension = (fileName: string): string => {
    const ext = fileName.substring(fileName.lastIndexOf('.')).toLowerCase();
    if (ext === '.py') return 'Python';
    if (ext === '.java') return 'Java';
    if (['.cpp', '.cc', '.cxx', '.c', '.h', '.hpp'].includes(ext)) return 'C++';
    if (['.js', '.jsx', '.mjs', '.cjs'].includes(ext)) return 'JavaScript';
    if (['.ts', '.tsx'].includes(ext)) return 'TypeScript';
    return 'Python';
  };

  const processFile = async (file: File) => {
    setErrorMsg('');
    const ext = file.name.substring(file.name.lastIndexOf('.')).toLowerCase();

    if (!SUPPORTED_EXTENSIONS.includes(ext)) {
      setErrorMsg(`Unsupported file type '${ext}'. Supported extensions: .py, .java, .cpp, .js, .ts`);
      return;
    }

    const language = detectLanguageFromExtension(file.name);

    try {
      // 1. Read file text locally
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = e.target?.result as string;
        if (text !== undefined) {
          onFileLoaded(text, file.name, language);
        }
      };
      reader.readAsText(file);

      // 2. Also send to upload API if needed
      try {
        await apiService.uploadFile(file);
      } catch (apiErr) {
        // Local fallback already loaded text
      }
    } catch (err: any) {
      setErrorMsg('Failed to read uploaded file.');
    }
  };

  const handleDragOver = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(true);
  };

  const handleDragLeave = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragOver(false);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFile(e.dataTransfer.files[0]);
    }
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFile(e.target.files[0]);
    }
  };

  return (
    <div className="space-y-2">
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-5 text-center cursor-pointer transition-all ${
          isDragOver
            ? 'border-blue-500 bg-blue-500/10 shadow-lg shadow-blue-500/20'
            : hasCode
            ? 'border-slate-800 bg-slate-900/60 hover:border-slate-700'
            : 'border-slate-700 bg-slate-900/80 hover:border-blue-500/50 hover:bg-slate-800/80'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          onChange={handleFileSelect}
          accept={SUPPORTED_EXTENSIONS.join(',')}
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-2">
          <div className="p-3 bg-blue-600/10 border border-blue-500/20 rounded-full text-blue-400">
            <Upload className="w-5 h-5" />
          </div>

          {currentFilename && hasCode ? (
            <div className="space-y-1">
              <div className="flex items-center justify-center space-x-2 text-sm font-semibold text-white">
                <FileCode className="w-4 h-4 text-blue-400" />
                <span>{currentFilename}</span>
                <span className="text-xs px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 font-mono border border-blue-500/30">
                  {detectedLanguage}
                </span>
              </div>
              <p className="text-xs text-emerald-400 flex items-center justify-center gap-1">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Source file loaded successfully. Click or drag to replace.</span>
              </p>
            </div>
          ) : (
            <div className="space-y-1">
              <p className="text-sm font-semibold text-slate-200">
                Drag & drop a source file here, or{' '}
                <span className="text-blue-400 underline underline-offset-2">browse file</span>
              </p>
              <p className="text-xs text-slate-400">
                Supports <span className="font-mono text-slate-300">.py, .java, .cpp, .js, .ts</span>
              </p>
            </div>
          )}
        </div>
      </div>

      {errorMsg && (
        <div className="p-2.5 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-xs flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{errorMsg}</span>
        </div>
      )}
    </div>
  );
};
