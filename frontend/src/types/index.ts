export interface Finding {
  agent: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | string;
  issue: string;
  explanation: string;
  line: number;
}

export interface Remediation {
  issue: string;
  severity: string;
  line: number;
  why_it_is_problematic: string;
  recommended_fix: string;
  corrected_code_example: string;
  best_practice: string;
  references: string[];
}

export interface PRSummary {
  overall_status: 'Approved' | 'Approved with Suggestions' | 'Needs Changes' | 'Rejected' | string;
  overall_code_quality: number;
  overall_security_score: number;
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  top_risks: string[];
  code_quality_summary: string;
  security_summary: string;
  positive_observations: string[];
  recommended_next_steps: string[];
  estimated_remediation_effort: {
    critical: string;
    high: string;
    overall: string;
  };
  developer_comment: string;
}

export interface ReviewResult {
  status: string;
  language: string;
  execution_time_ms: number;
  summary: {
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    agent_status?: Record<string, string>;
  };
  findings: Finding[];
  remediation: Remediation[];
  pr_summary: PRSummary;
}

export interface ReviewResponse {
  status: string;
  language: string;
  review: ReviewResult;
}

export interface ChatSource {
  document: string;
  score: number;
}

export interface ChatResponse {
  answer: string;
  sources: ChatSource[];
  related_topics: string[];
}

export interface ExplainFindingResponse {
  status: string;
  finding: Finding;
  answer: string;
  explanation: string;
  sources: ChatSource[];
  related_topics: string[];
}

export interface AskRemediationResponse {
  status: string;
  finding: Finding;
  remediation: Remediation;
  conversational_explanation: string;
  answer: string;
  sources: ChatSource[];
  related_topics: string[];
}

export interface HistoricalReview {
  id: string;
  timestamp: string;
  filename: string;
  language: string;
  code: string;
  result: ReviewResult;
}
