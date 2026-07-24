import React, { useState, useEffect, useRef } from 'react';
import { Bot, Send, User, Sparkles, BookOpen, Loader2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { apiService } from '../services/api';
import type { ChatSource, Finding } from '../types';

interface Message {
  id: string;
  sender: 'user' | 'assistant';
  text: string;
  sources?: ChatSource[];
  related_topics?: string[];
  timestamp: string;
}

const STARTER_QUESTIONS = [
  'Explain SQL Injection.',
  'Why is eval() dangerous?',
  'Explain Cyclomatic Complexity.',
  'Why was this issue marked Critical?',
  'Give me the secure version of this code.'
];

export const ChatAssistant: React.FC = () => {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: 'welcome',
      sender: 'assistant',
      text: 'Hello! I am your **RAG Secure Coding Assistant** grounded in OWASP Top 10 security standards, PEP 8 guidelines, and AST analysis rules. How can I assist with your code review?',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [input, setInput] = useState('');
  const [loading, setLoading] = useState(false);
  const [activeFinding, setActiveFinding] = useState<Finding | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    const cachedFinding = localStorage.getItem('chat_prefill_finding');
    if (cachedFinding) {
      try {
        const finding: Finding = JSON.parse(cachedFinding);
        setActiveFinding(finding);
        localStorage.removeItem('chat_prefill_finding');

        const initialPrompt = `Explain this finding on Line ${finding.line}: ${finding.issue}. Details: ${finding.explanation}`;
        handleSendMessage(initialPrompt, [finding]);
      } catch (e) {
        console.error('Failed to parse prefilled finding:', e);
      }
    }
  }, []);

  const handleSendMessage = async (queryText?: string, findingsContext?: Finding[]) => {
    const textToSend = queryText || input;
    if (!textToSend.trim() || loading) return;

    const userMsg: Message = {
      id: `user_${Date.now()}`,
      sender: 'user',
      text: textToSend,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };

    setMessages((prev) => [...prev, userMsg]);
    if (!queryText) setInput('');
    setLoading(true);

    try {
      const response = await apiService.chat(
        textToSend,
        findingsContext || (activeFinding ? [activeFinding] : undefined)
      );

      const assistantMsg: Message = {
        id: `assistant_${Date.now()}`,
        sender: 'assistant',
        text: response.answer,
        sources: response.sources,
        related_topics: response.related_topics,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };

      setMessages((prev) => [...prev, assistantMsg]);
    } catch (err: any) {
      const errorMsg: Message = {
        id: `error_${Date.now()}`,
        sender: 'assistant',
        text: 'Sorry, I encountered an error connecting to the RAG knowledge base. Please ensure the backend API is running.',
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      setMessages((prev) => [...prev, errorMsg]);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 h-[calc(100vh-5rem)] flex flex-col space-y-4">
      <div className="glass-panel p-4 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <div className="p-2 bg-blue-600/20 border border-blue-500/30 rounded-xl text-blue-400">
            <Bot className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-bold text-white flex items-center gap-2">
              RAG Conversational Code Assistant
              <span className="text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.5 rounded-full font-medium">
                ChromaDB Connected
              </span>
            </h1>
            <p className="text-xs text-slate-400">Ask questions grounded in indexed secure coding PDFs & OWASP standards</p>
          </div>
        </div>

        {activeFinding && (
          <div className="flex items-center space-x-2 bg-blue-950/40 border border-blue-500/30 px-3 py-1.5 rounded-xl text-xs">
            <span className="text-slate-400">Context:</span>
            <span className="font-semibold text-blue-300">Line {activeFinding.line}: {activeFinding.issue}</span>
            <button onClick={() => setActiveFinding(null)} className="text-slate-500 hover:text-slate-300 ml-1">
              &times;
            </button>
          </div>
        )}
      </div>

      <div className="flex items-center space-x-2 overflow-x-auto pb-1 text-xs">
        <span className="text-slate-400 font-medium whitespace-nowrap">Suggested Queries:</span>
        {STARTER_QUESTIONS.map((q, idx) => (
          <button
            key={idx}
            onClick={() => handleSendMessage(q)}
            disabled={loading}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg whitespace-nowrap cursor-pointer transition-all disabled:opacity-50"
          >
            {q}
          </button>
        ))}
      </div>

      <div className="flex-1 glass-panel p-4 overflow-y-auto space-y-4">
        {messages.map((msg) => (
          <div
            key={msg.id}
            className={`flex items-start space-x-3 ${msg.sender === 'user' ? 'flex-row-reverse space-x-reverse' : ''}`}
          >
            <div
              className={`p-2 rounded-xl text-white ${
                msg.sender === 'user' ? 'bg-blue-600' : 'bg-slate-800 border border-slate-700 text-blue-400'
              }`}
            >
              {msg.sender === 'user' ? <User className="w-4 h-4" /> : <Bot className="w-4 h-4" />}
            </div>

            <div className={`max-w-2xl space-y-2 ${msg.sender === 'user' ? 'items-end' : ''}`}>
              <div
                className={`p-4 rounded-2xl text-xs sm:text-sm leading-relaxed ${
                  msg.sender === 'user'
                    ? 'bg-blue-600 text-white rounded-tr-none'
                    : 'bg-slate-900/90 text-slate-200 border border-slate-800 rounded-tl-none'
                }`}
              >
                {msg.sender === 'user' ? (
                  <p>{msg.text}</p>
                ) : (
                  <div className="prose prose-invert prose-xs max-w-none space-y-2">
                    <ReactMarkdown>{msg.text}</ReactMarkdown>
                  </div>
                )}
                <span className="block text-[10px] text-slate-400 mt-2 text-right">{msg.timestamp}</span>
              </div>

              {msg.sources && msg.sources.length > 0 && (
                <div className="space-y-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1">
                    <BookOpen className="w-3 h-3 text-blue-400" />
                    Sources & Citations:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {msg.sources.map((src, sIdx) => (
                      <span
                        key={sIdx}
                        className="inline-flex items-center space-x-1 px-2.5 py-1 rounded bg-blue-950/40 border border-blue-500/20 text-[11px] text-blue-300"
                      >
                        <span>📄 {src.document}</span>
                        <span className="text-blue-400 font-bold">({Math.round(src.score * 100)}%)</span>
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {msg.related_topics && msg.related_topics.length > 0 && (
                <div className="space-y-1 pt-1">
                  <span className="text-[11px] font-bold text-slate-400 uppercase tracking-wider flex items-center gap-1">
                    <Sparkles className="w-3 h-3 text-emerald-400" />
                    Related Topics:
                  </span>
                  <div className="flex flex-wrap gap-1.5">
                    {msg.related_topics.map((topic, tIdx) => (
                      <button
                        key={tIdx}
                        onClick={() => handleSendMessage(topic)}
                        className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 rounded-lg text-[11px] cursor-pointer transition-all"
                      >
                        + {topic}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex items-center space-x-3">
            <div className="p-2 bg-slate-800 border border-slate-700 rounded-xl text-blue-400">
              <Bot className="w-4 h-4" />
            </div>
            <div className="p-3 rounded-2xl bg-slate-900/90 border border-slate-800 text-xs text-slate-400 flex items-center space-x-2">
              <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
              <span>Searching ChromaDB knowledge base & synthesizing grounded response...</span>
            </div>
          </div>
        )}

        <div ref={messagesEndRef} />
      </div>

      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        className="glass-panel p-2 flex items-center space-x-2 border border-slate-800"
      >
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask a question about SQL injection, eval(), cyclomatic complexity, or your findings..."
          className="flex-1 bg-transparent px-4 py-2.5 text-sm text-slate-200 focus:outline-none placeholder-slate-500"
          disabled={loading}
        />
        <button
          type="submit"
          disabled={!input.trim() || loading}
          className="p-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-xl transition-all cursor-pointer"
        >
          <Send className="w-4 h-4" />
        </button>
      </form>
    </div>
  );
};
