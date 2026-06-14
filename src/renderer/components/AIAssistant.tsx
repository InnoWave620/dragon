import React, { useState, useEffect, useRef } from 'react';
import { 
  Send, 
  MessageSquareCode, 
  ShieldAlert, 
  Copy, 
  Check, 
  Bot, 
  User, 
  Sparkles,
  ArrowRight
} from 'lucide-react';

interface Finding {
  id: string;
  title: string;
  severity: string;
  description: string;
  impact: string;
  remediation: string;
}

interface Message {
  sender: 'user' | 'ai';
  text: string;
  codeSnippet?: string;
  language?: string;
  timestamp: string;
}

interface AIAssistantProps {
  findings: Finding[];
}

export default function AIAssistant({ findings }: AIAssistantProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      sender: 'ai',
      text: 'Hello! I am your Dragon AI Security Advisor. Select an active vulnerability from the sidebar, or type a security auditing question (e.g., "How do I fix XSS?" or "Explain secure cookie flags") to get started.',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [copiedId, setCopiedId] = useState<number | null>(null);
  const [isTyping, setIsTyping] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Check for deep-linked findings in sessionStorage (routed from VulnerabilityExplorer)
  useEffect(() => {
    const contextStr = sessionStorage.getItem('ai_context_finding');
    if (contextStr) {
      try {
        const finding = JSON.parse(contextStr);
        sessionStorage.removeItem('ai_context_finding'); // Consume context
        setSelectedFinding(finding);
        triggerFindingQuery(finding);
      } catch (e) {
        console.error(e);
      }
    }
  }, []);

  // Scroll to bottom when messages list grows
  useEffect(() => {
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({ behavior: 'smooth' });
    }
  }, [messages, isTyping]);

  const triggerFindingQuery = async (finding: Finding) => {
    setIsTyping(true);
    
    // 1. Append User Message
    const userMsg: Message = {
      sender: 'user',
      text: `Explain and generate remediation code for vulnerability: "${finding.title}"`,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      // 2. Fetch AI advice via IPC bridge
      const aiResponse = await window.electronAPI.ai.chat('', finding);
      
      const responseMsg: Message = {
        sender: 'ai',
        text: aiResponse.answer,
        codeSnippet: aiResponse.codeSnippet,
        language: aiResponse.language,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      
      setMessages(prev => [...prev, responseMsg]);
    } catch (e: any) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: `Error connecting to AI Advisor: ${e.message}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleSendMessage = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!inputValue.trim()) return;

    const query = inputValue;
    setInputValue('');
    setIsTyping(true);

    // Append User Message
    const userMsg: Message = {
      sender: 'user',
      text: query,
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
    };
    setMessages(prev => [...prev, userMsg]);

    try {
      // Call AI Chat API
      const aiResponse = await window.electronAPI.ai.chat(query, selectedFinding || undefined);
      
      const responseMsg: Message = {
        sender: 'ai',
        text: aiResponse.answer,
        codeSnippet: aiResponse.codeSnippet,
        language: aiResponse.language,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      };
      
      setMessages(prev => [...prev, responseMsg]);
    } catch (e: any) {
      setMessages(prev => [...prev, {
        sender: 'ai',
        text: `Connection error: ${e.message}`,
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
      }]);
    } finally {
      setIsTyping(false);
    }
  };

  const handleCopyCode = (code: string, index: number) => {
    navigator.clipboard.writeText(code);
    setCopiedId(index);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 h-[calc(100vh-10rem)] overflow-hidden">
      
      {/* VULNERABILITY CONTEXT SIDEBAR (1/4 Width) */}
      <div className="glass-card p-4 flex flex-col space-y-4 h-full overflow-y-auto">
        <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center space-x-2 border-b border-dark-border pb-3 shrink-0">
          <ShieldAlert className="w-4 h-4 text-cyber-rose" />
          <span>Active Findings</span>
        </h3>

        <div className="flex-1 space-y-2">
          {findings.length > 0 ? (
            findings.map((f) => (
              <button
                key={f.id}
                onClick={() => {
                  setSelectedFinding(f);
                  triggerFindingQuery(f);
                }}
                className={`w-full text-left p-2.5 rounded-lg border text-xs transition-all flex items-start justify-between group ${
                  selectedFinding?.id === f.id 
                    ? 'bg-cyber-cyan/10 border-cyber-cyan/30 text-white' 
                    : 'bg-dark-surface border-dark-border text-gray-400 hover:border-gray-700 hover:text-gray-200'
                }`}
              >
                <div className="truncate pr-2 w-full">
                  <span className="block font-semibold truncate">{f.title}</span>
                  <span className="text-[9px] uppercase tracking-wider text-gray-500 font-bold group-hover:text-gray-400">
                    {f.severity}
                  </span>
                </div>
                <ArrowRight className="w-3.5 h-3.5 mt-0.5 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity" />
              </button>
            ))
          ) : (
            <div className="text-center py-10 text-gray-600 text-xs">
              No findings available to remediate.
            </div>
          )}
        </div>
      </div>

      {/* CHAT SESSION AREA (3/4 Width) */}
      <div className="lg:col-span-3 glass-card flex flex-col justify-between h-full overflow-hidden">
        
        {/* Chat Area Header */}
        <div className="px-6 py-4 border-b border-dark-border bg-dark-surface/50 flex items-center justify-between shrink-0">
          <div className="flex items-center space-x-2.5">
            <Bot className="w-5 h-5 text-cyber-cyan shadow-glow-cyan" />
            <div>
              <h3 className="text-sm font-bold text-white tracking-wide">Dragon AI Advisor</h3>
              <p className="text-[10px] text-gray-500 font-medium">Context: {selectedFinding ? `Auditing "${selectedFinding.title}"` : 'General Security Audit'}</p>
            </div>
          </div>
          {selectedFinding && (
            <button 
              onClick={() => setSelectedFinding(null)}
              className="text-[10px] bg-dark-border text-gray-400 hover:text-white px-2.5 py-1 rounded transition-colors"
            >
              Clear Context
            </button>
          )}
        </div>

        {/* Message Feed Container */}
        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          {messages.map((msg, index) => {
            const isAI = msg.sender === 'ai';
            return (
              <div 
                key={index} 
                className={`flex space-x-3 max-w-2xl ${isAI ? '' : 'ml-auto flex-row-reverse space-x-reverse'}`}
              >
                {/* Avatar Icon */}
                <div className={`p-2 rounded-lg border shrink-0 h-9 w-9 flex items-center justify-center ${
                  isAI 
                    ? 'bg-cyber-cyan/5 border-cyber-cyan/25 text-cyber-cyan' 
                    : 'bg-dark-border border-gray-700 text-white'
                }`}>
                  {isAI ? <Bot className="w-5 h-5" /> : <User className="w-5 h-5" />}
                </div>

                {/* Message Content Bubble */}
                <div className="space-y-2">
                  <div className={`p-4 rounded-xl text-xs leading-relaxed border ${
                    isAI 
                      ? 'bg-dark-card border-dark-border text-gray-300' 
                      : 'bg-cyber-cyan/5 border-cyber-cyan/20 text-white'
                  }`}>
                    {/* Parse text markdown headers in a basic way */}
                    {msg.text.split('\n').map((line, lIdx) => {
                      if (line.startsWith('###')) {
                        return <h4 key={lIdx} className="font-extrabold text-white text-xs mt-3 mb-1.5 uppercase tracking-wider">{line.replace('###', '').trim()}</h4>;
                      }
                      if (line.startsWith('**')) {
                        return <p key={lIdx} className="font-bold text-gray-200 mt-2">{line.replace(/\*\*/g, '').trim()}</p>;
                      }
                      return <p key={lIdx} className="mb-1">{line}</p>;
                    })}
                  </div>

                  {/* Render attached Code Snippets if any */}
                  {msg.codeSnippet && (
                    <div className="border border-dark-border rounded-lg overflow-hidden bg-dark-bg/80 max-w-xl">
                      <div className="px-4 py-1.5 bg-dark-surface border-b border-dark-border flex items-center justify-between text-[9px] text-gray-500 font-bold uppercase tracking-wider">
                        <span>{msg.language || 'Code block'}</span>
                        <button 
                          onClick={() => handleCopyCode(msg.codeSnippet!, index)}
                          className="flex items-center space-x-1 hover:text-white transition-colors"
                        >
                          {copiedId === index ? (
                            <>
                              <Check className="w-3 h-3 text-cyber-emerald" />
                              <span className="text-cyber-emerald">Copied</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3 h-3" />
                              <span>Copy</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="p-4 overflow-x-auto text-[11px] font-mono text-cyan-300 max-h-48 leading-relaxed">
                        <code>{msg.codeSnippet}</code>
                      </pre>
                    </div>
                  )}

                  {/* Timestamp label */}
                  <span className={`block text-[9px] text-gray-600 ${isAI ? '' : 'text-right'}`}>{msg.timestamp}</span>
                </div>
              </div>
            );
          })}

          {/* Typing Indicator */}
          {isTyping && (
            <div className="flex space-x-3 max-w-sm">
              <div className="p-2 rounded-lg border bg-cyber-cyan/5 border-cyber-cyan/25 text-cyber-cyan h-9 w-9 flex items-center justify-center">
                <Bot className="w-5 h-5 animate-pulse" />
              </div>
              <div className="p-4 rounded-xl border bg-dark-card border-dark-border flex items-center space-x-1 py-3">
                <span className="w-1.5 h-1.5 bg-cyber-cyan rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                <span className="w-1.5 h-1.5 bg-cyber-cyan rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                <span className="w-1.5 h-1.5 bg-cyber-cyan rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
              </div>
            </div>
          )}
        </div>

        {/* Input Form Bar */}
        <form onSubmit={handleSendMessage} className="p-4 border-t border-dark-border bg-dark-surface/30 flex items-center space-x-3 shrink-0">
          <input 
            type="text" 
            placeholder={selectedFinding ? `Ask about "${selectedFinding.title}" fix...` : "Type a general security auditing query..."}
            value={inputValue}
            onChange={e => setInputValue(e.target.value)}
            disabled={isTyping}
            className="input-cyber flex-1 text-xs py-2.5"
          />
          <button 
            type="submit" 
            disabled={!inputValue.trim() || isTyping}
            className="btn-cyber-cyan p-2.5 flex items-center justify-center rounded-lg disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Send className="w-4 h-4" />
          </button>
        </form>

      </div>

    </div>
  );
}
