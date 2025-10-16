import { useEffect, useRef, useState } from 'react'
import { GetServerSideProps } from 'next'
import { verifyToken } from '../lib/auth'
import * as cookie from 'cookie'
import Layout from '../components/Layout'
import Sidebar from '../components/Sidebar'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
type ChatMessage = { role: 'user' | 'assistant'; content: string }
interface ChatPageProps { userId?: number; username?: string }
type ChatThread = { id: string; title: string; messages: ChatMessage[]; createdAt: number; updatedAt: number }

export default function ChatPage({ userId, username }: ChatPageProps) {
  const [message, setMessage] = useState('')
  const [threads, setThreads] = useState<ChatThread[]>([])
  const [activeThreadId, setActiveThreadId] = useState<string>('')
  const [loading, setLoading] = useState(false)
  const [threadsOpen, setThreadsOpen] = useState(true)
  const [copiedIdx, setCopiedIdx] = useState<number | null>(null)
  const bottomRef = useRef<HTMLDivElement | null>(null)
  const storageKey = `siem_chat_history_${userId ?? username ?? 'anon'}`
  const threadsKey = `siem_chat_threads_${userId ?? username ?? 'anon'}`

  const activeThread = threads.find(t => t.id === activeThreadId) || null
  const messages = activeThread?.messages || []

  // Load threads and migrate any legacy single-thread history on mount/user change
  useEffect(() => {
    try {
      const storedThreads = localStorage.getItem(threadsKey)
      if (storedThreads) {
        const parsed = JSON.parse(storedThreads) as ChatThread[]
        setThreads(parsed)
        setActiveThreadId(parsed[0]?.id || '')
      } else {
        // migrate from old per-user messages if present
        const legacy = localStorage.getItem(storageKey)
        const legacyMessages = legacy ? (JSON.parse(legacy) as ChatMessage[]) : []
        const initialThread: ChatThread = {
          id: String(Date.now()),
          title: legacyMessages[0]?.content?.slice(0, 30) || 'New Chat',
          messages: legacyMessages,
          createdAt: Date.now(),
          updatedAt: Date.now(),
        }
        const initialList = [initialThread]
        setThreads(initialList)
        setActiveThreadId(initialThread.id)
        localStorage.setItem(threadsKey, JSON.stringify(initialList))
      }
    } catch {
      // ignore parse errors
    }
  }, [storageKey, threadsKey])

  // Persist threads whenever they change
  useEffect(() => {
    try {
      if (threads.length) {
        localStorage.setItem(threadsKey, JSON.stringify(threads))
      }
    } catch {
      // ignore
    }
  }, [threads, threadsKey])

  // Auto-scroll to bottom when messages change
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, loading])

  const createThread = () => {
    const now = Date.now()
    const newThread: ChatThread = {
      id: String(now),
      title: 'New Chat',
      messages: [],
      createdAt: now,
      updatedAt: now,
    }
    setThreads(prev => [newThread, ...prev])
    setActiveThreadId(newThread.id)
  }

  const renameThread = (id: string) => {
    const title = prompt('Rename conversation:')
    if (!title) return
    setThreads(prev => prev.map(t => t.id === id ? { ...t, title } : t))
  }

  const deleteThread = (id: string) => {
    if (!confirm('Delete this conversation?')) return
    setThreads(prev => {
      const filtered = prev.filter(t => t.id !== id)
      const nextActive = filtered[0]?.id || ''
      setActiveThreadId(nextActive)
      return filtered
    })
  }

  const handleSend = async (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = message.trim()
    if (!trimmed) return

    // ensure we have an active thread
    let threadId = activeThreadId
    if (!threadId) {
      const now = Date.now()
      const newThread: ChatThread = {
        id: String(now),
        title: trimmed.slice(0, 30) || 'New Chat',
        messages: [],
        createdAt: now,
        updatedAt: now,
      }
      setThreads(prev => [newThread, ...prev])
      setActiveThreadId(newThread.id)
      threadId = newThread.id
    }

    // optimistic append of user message to the active thread
    setThreads(prev => prev.map(t =>
      t.id === threadId ? { ...t, messages: [...t.messages, { role: 'user', content: trimmed }], title: t.messages.length === 0 ? (trimmed.slice(0, 30) || t.title) : t.title, updatedAt: Date.now() } : t
    ))
    setMessage('')
    setLoading(true)

    try {
      const res = await fetch(process.env.NEXT_PUBLIC_CHAT_API_URL || 'http://localhost:5001/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: trimmed }),
      })
      const data = await res.json()
      const aiText = (data && data.response) ? String(data.response) : 'No response'
      const currentId = threadId
      setThreads(prev => prev.map(t =>
        t.id === currentId ? { ...t, messages: [...t.messages, { role: 'assistant', content: aiText }], updatedAt: Date.now() } : t
      ))
    } catch (err: any) {
      const errMsg = `Error: ${err?.message || 'Request failed'}`
      const currentId = threadId
      setThreads(prev => prev.map(t =>
        t.id === currentId ? { ...t, messages: [...t.messages, { role: 'assistant', content: errMsg }], updatedAt: Date.now() } : t
      ))
    } finally {
      setLoading(false)
    }
  }

  return (
    <Layout>
      <Sidebar />
      {/* Page content container shifted to the right of fixed app sidebar */}
      <div className="pt-16 ml-60 pr-6">
        {/* <h1 className="text-xl font-semibold px-8 pb-4 pt-4 pl-4">SIEM Chat</h1> */}
        <div className="flex items-center justify-between px-8 pb-4 pt-4 pl-4">
          {/* <h1 className="text-xl font-semibold">SIEM Chat</h1> */}
          <button
            onClick={() => setThreadsOpen(!threadsOpen)}
            className="text-sm px-3 py-1 border rounded hover:bg-gray-50"
            aria-expanded={threadsOpen}
            aria-controls="chat-threads-panel"
          >
            {threadsOpen ? 'Hide Conversations' : 'Show Conversations'}
          </button>
        </div>
        <div className="flex gap-4">
          {/* Threads sidebar */}
          {threadsOpen && (
            <aside id="chat-threads-panel" className="w-64 bg-white border rounded-lg shadow-sm h-[70vh] overflow-hidden">
              <div className="p-3 border-b flex items-center justify-between">
                <span className="font-medium">Conversations</span>
                <button onClick={createThread} className="text-sm px-2 py-1 bg-blue-600 text-white rounded">New</button>
              </div>
              <div className="overflow-y-auto h-full">
                {threads.length === 0 && (
                  <div className="p-4 text-sm text-gray-500">No conversations</div>
                )}
                {threads.map(t => (
                  <div key={t.id} className={`px-3 py-2 border-b cursor-pointer ${t.id === activeThreadId ? 'bg-blue-50' : 'hover:bg-gray-50'}`}>
                    <div className="flex items-center justify-between gap-2">
                      <button className="flex-1 text-left truncate" onClick={() => setActiveThreadId(t.id)}>
                        {t.title || 'Untitled'}
                      </button>
                      <div className="flex items-center gap-1">
                        <button title="Rename" onClick={() => renameThread(t.id)} className="text-xs px-2 py-1 border rounded">Ren</button>
                        <button title="Delete" onClick={() => deleteThread(t.id)} className="text-xs px-2 py-1 border rounded">Del</button>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </aside>
          )}

          {/* Chat panel */}
          <section className="flex-1">
            {/* Messages list */}
            <div className="flex flex-col gap-3 max-h-[60vh] overflow-y-auto pr-1 bg-white border rounded-lg shadow-sm p-4">
              {messages.map((m, idx) => (
                <div
                  key={idx}
                  className={`group relative flex ${m.role === 'user' ? 'justify-end' : 'justify-start'}`}
                >
                  <div
                    className={`${m.role === 'user' ? 'bg-blue-600 text-white' : 'bg-gray-100 text-gray-900'} px-3 py-2 rounded-lg max-w-[80%] relative`}
                  >
                    {m.role === 'assistant' ? (
                      <ReactMarkdown remarkPlugins={[remarkGfm]} className="prose prose-sm max-w-none">
                        {m.content}
                      </ReactMarkdown>
                    ) : (
                      <span className="whitespace-pre-wrap">{m.content}</span>
                    )}
                    {m.role === 'user' && (
                      <button
                        onClick={async () => {
                          try {
                            await navigator.clipboard.writeText(m.content)
                            setCopiedIdx(idx)
                            setTimeout(() => setCopiedIdx(null), 1200)
                          } catch {}
                        }}
                        title="Copy"
                        className={`absolute top-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity duration-150 z-10 inline-flex items-center gap-1 text-xs px-2 py-1 rounded-full border bg-white/95 backdrop-blur shadow text-gray-700 hover:bg-white`}
                      >
                        <svg className="h-3.5 w-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                        </svg>
                        {copiedIdx === idx ? 'Copied' : 'Copy'}
                      </button>
                    )}
                  </div>
                </div>
              ))}
              {loading && (
                <div className="flex justify-start">
                  <div className="bg-gray-100 text-gray-900 px-3 py-2 rounded-lg">Thinking…</div>
                </div>
              )}
              <div ref={bottomRef} />
            </div>

            {/* Composer */}
            <form onSubmit={handleSend} className="flex gap-2 mt-3">
              <input
                className="flex-1 border rounded px-3 py-2"
                placeholder="Ask for a report or insights..."
                value={message}
                onChange={(e) => setMessage(e.target.value)}
              />
              <button
                className="px-4 py-2 bg-blue-600 text-white rounded disabled:opacity-50"
                disabled={loading}
                type="submit"
              >
                {loading ? 'Sending...' : 'Send'}
              </button>
            </form>
          </section>
        </div>
      </div>
    </Layout>
  )
}




export const getServerSideProps: GetServerSideProps<ChatPageProps> = async (ctx) => {
  const cookies = ctx.req.headers.cookie || ''
  const { token } = cookie.parse(cookies)
  if (!token) return { redirect: { destination: '/login', permanent: false } }

  try {
    const payload: any = verifyToken(token)
    if (!payload) throw new Error('invalid')
    return { props: { userId: payload.id, username: payload.username } }
  } catch {
    return { redirect: { destination: '/login', permanent: false } }
  }
}