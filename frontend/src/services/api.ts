import axios from 'axios';
import type {
  ReviewResponse,
  ChatResponse,
  ExplainFindingResponse,
  AskRemediationResponse,
  Finding
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8001';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 600000,
});

export const apiService = {
  async reviewCode(code: string, language: string = 'python'): Promise<ReviewResponse> {
    const response = await apiClient.post<ReviewResponse>('/review-code', {
      code,
      language
    });
    return response.data;
  },

  async submitCode(code: string, language: string = 'python') {
    const response = await apiClient.post('/submit-code', {
      code,
      language
    });
    return response.data;
  },

  async uploadFile(file: File) {
    const formData = new FormData();
    formData.append('file', file);

    const response = await apiClient.post('/upload-file', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  },

  async chat(
    question: string,
    optional_findings?: Finding[],
    optional_code?: string,
    remediations?: any[],
    pr_summary?: any,
    code_quality_score?: number,
    security_score?: number
  ): Promise<ChatResponse> {
    const response = await apiClient.post<ChatResponse>('/chat', {
      question,
      optional_findings,
      optional_code,
      remediations,
      pr_summary,
      code_quality_score,
      security_score
    });
    return response.data;
  },

  async explainFinding(finding: Finding): Promise<ExplainFindingResponse> {
    const response = await apiClient.post<ExplainFindingResponse>('/explain-finding', {
      finding
    });
    return response.data;
  },

  async askRemediation(finding: Finding): Promise<AskRemediationResponse> {
    const response = await apiClient.post<AskRemediationResponse>('/ask-remediation', {
      finding
    });
    return response.data;
  },

  async generateReport(reviewData: any, format: string = 'both') {
    const response = await apiClient.post('/generate-report', {
      review: reviewData,
      format
    });
    return response.data;
  },

  async downloadReportPdf(reviewData: any): Promise<Blob> {
    const response = await apiClient.post('/download-report/pdf', {
      review: reviewData
    }, {
      responseType: 'blob'
    });
    return response.data;
  },

  async downloadReportHtml(reviewData: any): Promise<Blob> {
    const response = await apiClient.post('/download-report/html', {
      review: reviewData
    }, {
      responseType: 'blob'
    });
    return response.data;
  },

  getReportDownloadUrl(filename: string): string {
    return `${API_BASE_URL}/download-report/${filename}`;
  }
};
