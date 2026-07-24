import type { HistoricalReview, ReviewResult } from '../types';

const STORAGE_KEY = 'ai_code_review_history_v1';

export const storageService = {
  getReviewHistory(): HistoricalReview[] {
    try {
      const data = localStorage.getItem(STORAGE_KEY);
      if (!data) return [];
      return JSON.parse(data) as HistoricalReview[];
    } catch (e) {
      console.error('Failed to load review history:', e);
      return [];
    }
  },

  saveReviewToHistory(
    code: string,
    filename: string,
    language: string,
    result: ReviewResult
  ): HistoricalReview {
    const history = this.getReviewHistory();
    const newEntry: HistoricalReview = {
      id: `rev_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`,
      timestamp: new Date().toISOString(),
      filename: filename || 'snippet.py',
      language: language || 'Python',
      code,
      result
    };

    const updatedHistory = [newEntry, ...history.slice(0, 49)];
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updatedHistory));
    } catch (e) {
      console.error('Failed to save review to history:', e);
    }

    return newEntry;
  },

  deleteReview(id: string): HistoricalReview[] {
    const history = this.getReviewHistory();
    const updated = history.filter((item) => item.id !== id);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(updated));
    } catch (e) {
      console.error('Failed to delete review from history:', e);
    }
    return updated;
  },

  clearHistory(): void {
    try {
      localStorage.removeItem(STORAGE_KEY);
    } catch (e) {
      console.error('Failed to clear history:', e);
    }
  }
};
