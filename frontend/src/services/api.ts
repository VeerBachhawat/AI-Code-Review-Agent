import axios from 'axios';
import type {
  ReviewResponse,
  ChatResponse,
  ExplainFindingResponse,
  AskRemediationResponse,
  Finding
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
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

  async chat(question: string, optional_findings?: Finding[], optional_code?: string): Promise<ChatResponse> {
    const response = await apiClient.post<ChatResponse>('/chat', {
      question,
      optional_findings,
      optional_code
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
  }
};
