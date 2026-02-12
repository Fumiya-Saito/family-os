import { Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { csrf } from 'hono/csrf'
import { createClient } from '@supabase/supabase-js'
import { GoogleGenerativeAI } from '@google/generative-ai'
import { messagingApi, WebhookEvent } from '@line/bot-sdk'
import { z } from 'zod'
import { sign, verify } from 'hono/jwt'
import { generateFlexMessages, createConfirmBubble, createSettingsBubble, createHelpBubble } from './flexMessages'

type Bindings = {
  GOOGLE_CLIENT_ID: string
  GOOGLE_CLIENT_SECRET: string
  GOOGLE_REDIRECT_URI: string
  GEMINI_API_KEY: string
  SUPABASE_URL: string
  SUPABASE_KEY: string
  LINE_CHANNEL_SECRET: string
  LINE_CHANNEL_ACCESS_TOKEN: string
  ALLOWED_USERS: string
  JWT_SECRET: string
  ENVIRONMENT?: string
  LINE_LIFF_ID: string
  LINE_CHANNEL_ID: string
}

type GoogleTokenResponse = {
  access_token: string
  expires_in: number
  refresh_token?: string
  scope: string
  token_type: string
  error?: string
  error_description?: string
}

const app = new Hono<{ Bindings: Bindings }>()

app.use('/settings/*', csrf())

// -- Zod Schema --
const EventSchema = z.object({
  summary: z.string(),
  start: z.string(),
  end: z.string().nullable().optional(),
  location: z.string().nullable().optional(),
  description: z.string().nullable().optional(),
  target: z.string().nullable().optional()
})
const ResponseSchema = z.object({
  events: z.array(EventSchema)
})

// --- Helpers ---

async function fetchWithRetry(url: string, options: RequestInit, retries = 3): Promise<Response> {
  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(url, options)
      if (res.status < 500) return res
      throw new Error(`${res.status}`)
    } catch (err) {
      if (i === retries - 1) throw err
      await new Promise(r => setTimeout(r, 500 * Math.pow(2, i)))
    }
  }
  throw new Error('Max retries')
}

function sanitizeText(text?: string | null, maxLength = 500): string {
  if (!text) return ''
  const cleaned = text.replace(/<[^>]*>?/gm, '').replace(/[\u0000-\u001F\u007F-\u009F]/g, '').trim()
  return cleaned.length > maxLength ? cleaned.slice(0, maxLength) + '...' : cleaned
}

function extractJson(text: string): string {
  let cleanText = text.replace(/```json|```/g, '').trim()
  const firstOpen = cleanText.indexOf('{')
  const lastClose = cleanText.lastIndexOf('}')
  if (firstOpen !== -1 && lastClose !== -1) {
    cleanText = cleanText.substring(firstOpen, lastClose + 1)
  }
  return cleanText.replace(/,\s*}/g, '}').replace(/,\s*]/g, ']')
}

async function verifyLineSignature(body: string, signature: string, secret: string): Promise<boolean> {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey('raw', encoder.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify'])
  const signatureBytes = Uint8Array.from(atob(signature), c => c.charCodeAt(0))
  return await crypto.subtle.verify('HMAC', key, signatureBytes, encoder.encode(body))
}

// 書き込み可能なカレンダー一覧を取得
async function getWritableCalendars(accessToken: string) {
  try {
    const res = await fetchWithRetry('https://www.googleapis.com/calendar/v3/users/me/calendarList', {
      headers: { Authorization: `Bearer ${accessToken}` }
    })
    if (!res.ok) return []
    const data = await res.json() as any
    // owner(所有者) または writer(編集者) 権限があるもののみ抽出
    return data.items.filter((c: any) => c.accessRole === 'owner' || c.accessRole === 'writer')
  } catch { return [] }
}

// --- Routes ---

app.get('/', (c) => c.text('Print2Cal Bot is Active! 🛡️'))

// Auth LP
app.get('/auth/landing', async (c) => {
  const userId = c.req.query('userId')
  if (!userId) return c.text('Error', 400)
  const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 600 }
  const stateToken = await sign(payload, c.env.JWT_SECRET, 'HS256')
  const url = new URL(c.req.url)
  const authUrl = `${url.origin}/auth?state=${stateToken}`
  return c.html(`<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css"><style>body{padding:2rem;text-align:center;}</style></head><body><main class="container"><h2>Google連携</h2><a href="${authUrl}" role="button">連携スタート 🚀</a></main></body></html>`)
})

// Auth Redirect
app.get('/auth', (c) => {
  const state = c.req.query('state')
  if (!state) return c.text('Error', 400)
  const params = new URLSearchParams({
    client_id: c.env.GOOGLE_CLIENT_ID,
    redirect_uri: c.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope: 'https://www.googleapis.com/auth/calendar.events https://www.googleapis.com/auth/calendar.readonly',
    access_type: 'offline',
    prompt: 'consent',
    state: state,
  })
  return c.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params.toString()}`)
})

// Auth Callback
app.get('/auth/callback', async (c) => {
  const code = c.req.query('code')
  const state = c.req.query('state')
  if (!code || !state) return c.text('Error', 400)

  let userId
  try {
    const payload = await verify(state, c.env.JWT_SECRET, 'HS256')
    userId = payload.sub as string
  } catch (e) { return c.text('Session Expired', 403) }

  let tokenRes
  try {
    tokenRes = await fetchWithRetry('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: c.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    })
  } catch (e) { return c.text('Auth Failed', 500) }
  
  const tokens = await tokenRes.json() as GoogleTokenResponse
  if (tokens.error) return c.text('Auth Error', 400)

  const supabase = createClient(c.env.SUPABASE_URL, c.env.SUPABASE_KEY)
  const { data: existing } = await supabase.from('google_auth').select('refresh_token').eq('user_id', userId).single()
  const refreshToken = tokens.refresh_token ?? existing?.refresh_token

  if (!refreshToken) return c.text('Error: No Refresh Token. Please revoke app access and try again.', 400)

  await supabase.from('users').upsert({ line_user_id: userId, display_name: 'User' })
  await supabase.from('google_auth').upsert({
    user_id: userId,
    refresh_token: refreshToken,
    access_token: tokens.access_token,
    expiry_date: Date.now() + (tokens.expires_in * 1000)
  })
  return c.html(`<h1>連携完了</h1><p>LINEに戻ってください。</p>`)
})

// --- Settings UI (LIFF Version) ---

// 1. LIFF エントリーポイント (フロントエンド)
// src/index.ts の app.get('/liff/entry') を書き換え
app.get('/liff/entry', (c) => {
  const liffId = c.env.LINE_LIFF_ID
  return c.html(`
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>プリカレ設定</title>
      <script charset="utf-8" src="https://static.line-scdn.net/liff/edge/2/sdk.js"></script>
      <style>
        body {
          font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
          display: flex;
          flex-direction: column;
          justify-content: center;
          align-items: center;
          height: 100vh;
          margin: 0;
          background-color: #f8f9fa;
          color: #333;
        }
        .spinner {
          width: 40px;
          height: 40px;
          border: 4px solid #e9ecef;
          border-top: 4px solid #2c3e50;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin-bottom: 20px;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .message { font-size: 16px; font-weight: bold; color: #2c3e50; }
        .sub-message { font-size: 12px; color: #888; margin-top: 8px; }
      </style>
    </head>
    <body>
      <div class="spinner"></div>
      <div class="message" id="status">認証しています...</div>
      <div class="sub-message">そのままお待ちください</div>

      <script>
        async function main() {
          try {
            // 1. LIFF初期化
            await liff.init({ liffId: "${liffId}" })
            
            // 2. 未ログインならログイン画面へ
            if (!liff.isLoggedIn()) {
              liff.login()
              return
            }
            
            // 3. IDトークンを取得
            const idToken = liff.getIDToken()
            
            // 4. バックエンド検証
            const res = await fetch('/settings/login-liff', {
              method: 'POST',
              headers: {'Content-Type': 'application/json'},
              body: JSON.stringify({ idToken })
            })
            
            if (res.ok) {
              window.location.href = '/settings'
            } else {
              document.getElementById('status').innerText = '認証に失敗しました。LINEから開き直してください。'
            }
          } catch(e) {
            document.getElementById('status').innerText = 'エラーが発生しました: ' + e
          }
        }
        main()
      </script>
    </body>
    </html>
  `)
})

// 2. LIFF ログイン検証 API (バックエンド)
app.post('/settings/login-liff', async (c) => {
  const body = await c.req.json()
  const idToken = body.idToken
  
  if (!idToken) return c.text('No Token', 400)

  // LINE公式APIで IDトークン を検証
  const params = new URLSearchParams()
  params.append('id_token', idToken)
  params.append('client_id', c.env.LINE_CHANNEL_ID)

  const verifyRes = await fetch('https://api.line.me/oauth2/v2.1/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params
  })

  if (!verifyRes.ok) {
    console.error('Token Verify Error:', await verifyRes.text())
    return c.text('Invalid Token', 403)
  }
  
  const profile = await verifyRes.json() as any
  const userId = profile.sub // ← これが「操作している本人」のLINE UserID

  // 自社セッション(Cookie)を発行
  const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 }
  const sessionToken = await sign(payload, c.env.JWT_SECRET, 'HS256')
  
  const isSecure = c.env.ENVIRONMENT !== 'local'
  setCookie(c, 'auth_token', sessionToken, { 
    httpOnly: true, 
    secure: isSecure, 
    path: '/', 
    maxAge: 3600,
    sameSite: 'Lax' 
  })
  
  return c.json({ success: true })
})

// Main Settings Page
// src/index.ts (GET /settings を置換)

// Main Settings Page
app.get('/settings', async (c) => {
  const token = getCookie(c, 'auth_token')
  if (!token) return c.text('セッション切れです。LINEから開き直してください。', 403)

  let userId
  try {
    const payload = await verify(token, c.env.JWT_SECRET, 'HS256')
    userId = payload.sub as string
  } catch (e) { return c.text('Invalid Session', 403) }

  const supabase = createClient(c.env.SUPABASE_URL, c.env.SUPABASE_KEY)
  
  // ユーザー設定（キーワード + カレンダーID）を取得
  const { data: userData } = await supabase.from('users').select('keywords, calendar_id').eq('line_user_id', userId).single()
  const keywords: string[] = userData?.keywords || []
  const currentCalendarId = userData?.calendar_id || 'primary'

  // カレンダー一覧を取得
  let calendars: any[] = []
  try {
    const { data: authData } = await supabase.from('google_auth').select('access_token').eq('user_id', userId).single()
    if (authData) {
      calendars = await getWritableCalendars(authData.access_token)
    }
  } catch(e) { console.error(e) }

  // src/index.ts (GET /settings のHTML生成部分のみ抜粋・置換)

  return c.html(`
    <!DOCTYPE html>
    <html lang="ja">
      <head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>プリカレ設定</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css">
        <style>
          /* ベーススタイル */
          body { padding:1rem; max-width:600px; margin:0 auto; color: #2c3e50; }
          
          /* カード風デザイン */
          section {
            background: #fff;
            padding: 20px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            margin-bottom: 24px;
            border: 1px solid #eee;
          }
          
          h3 { font-size: 1.1rem; border-bottom: 2px solid #f0f0f0; padding-bottom: 10px; margin-bottom: 15px; }
          p { font-size: 0.9rem; color: #666; margin-bottom: 15px; }
          small { color: #888; }

          /* カレンダー選択リスト */
          .cal-list { display: flex; flex-direction: column; gap: 8px; }
          .cal-item {
            position: relative;
            padding: 12px 16px;
            border: 2px solid #eee;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
          }
          /* ラジオボタンは隠して、ラベル全体をクリック可能に */
          .cal-item input[type="radio"] { display: none; }
          
          /* 選択時のスタイル */
          .cal-item:has(input:checked) {
            border-color: #3498db;
            background-color: #f0f8ff;
          }
          .cal-item:has(input:checked)::after {
            content: '✔';
            position: absolute;
            right: 15px;
            color: #3498db;
            font-weight: bold;
          }

          .cal-color { width: 14px; height: 14px; border-radius: 50%; margin-right: 12px; flex-shrink: 0; }
          .cal-name { font-weight: bold; font-size: 0.95rem; }
          .cal-badge { 
            font-size: 0.7rem; background: #eee; padding: 2px 6px; border-radius: 4px; margin-left: 8px; color: #555;
          }
          
          /* タグスタイル */
          .tag { display:inline-flex; align-items:center; background:#eef2f5; color:#333; padding:4px 10px; border-radius:20px; margin:4px; font-size: 0.9rem; }
          button.del { border:none; background:none; color:#999; cursor:pointer; padding:0 0 0 8px; font-size: 1.1rem; line-height: 1; }
          button.del:hover { color: #e74c3c; }
          
          /* ボタン */
          button[type="submit"] { background-color: #2c3e50; border: none; font-weight: bold; }
          button.secondary { background-color: #95a5a6; }
        </style>
      </head>
      <body>
        <main>
          
          <section>
            <h3>📅 予定の登録先（誰のカレンダー？）</h3>
            <p>
              プリントの予定を書き込むカレンダーを選んでください。<br>
              <small>例: 「家族共有用」や「お子様専用」のカレンダーに分けることができます。</small>
            </p>
            
            <form action="/settings/update_calendar" method="POST">
              ${calendars.length === 0 ? '<p style="color:#e74c3c;">⚠️ カレンダー情報を取得できませんでした。<br>Botのトーク画面に戻り、再度連携を行ってください。</p>' : ''}
              
              <div class="cal-list">
              ${calendars.map((c: any) => `
                <label class="cal-item">
                  <input type="radio" name="calendar_id" value="${c.id}" ${c.id === currentCalendarId ? 'checked' : ''}>
                  <span class="cal-color" style="background-color:${c.backgroundColor}"></span>
                  <div>
                    <span class="cal-name">${sanitizeText(c.summary, 20)}</span>
                    ${c.primary ? '<span class="cal-badge">いつものカレンダー</span>' : ''}
                    ${c.summary.includes('ファミリー') || c.summary.includes('家族') ? '<span class="cal-badge">家族共有</span>' : ''}
                  </div>
                </label>
              `).join('')}
              </div>
              
              <button type="submit" style="margin-top:20px;">保存先を変更する</button>
            </form>
          </section>

          <section>
            <h3>⚙️ 抽出するキーワード（学年・クラス）</h3>
            <p>
              自分に関係のある行事だけを自動でピックアップします。<br>
              <small>※何も設定しないと、プリントに書かれた全ての行事が登録されます。</small>
            </p>
            
            <article style="border:none; padding:0; box-shadow:none;">
              <div style="margin-bottom:15px;">
                ${keywords.length === 0 ? '<small>設定なし（全件登録）</small>' : ''}
                ${keywords.map((k: string) => `
                  <span class="tag">
                    ${sanitizeText(k, 20)}
                    <form action="/settings/update" method="POST" style="display:inline">
                      <input type="hidden" name="action" value="delete">
                      <input type="hidden" name="word" value="${sanitizeText(k)}">
                      <button type="submit" class="del">×</button>
                    </form>
                  </span>
                `).join('')}
              </div>
              
              <form action="/settings/update" method="POST" style="display:flex; gap:10px;">
                <input type="hidden" name="action" value="add">
                <input type="text" name="word" placeholder="例: 1年2組, 年長" required maxlength="20" style="margin-bottom:0;">
                <button type="submit" class="secondary" style="width:auto; white-space:nowrap;">追加</button>
              </form>
            </article>
          </section>

        </main>
      </body>
    </html>
  `)
})

// Update Calendar Action
app.post('/settings/update_calendar', async (c) => {
  const token = getCookie(c, 'auth_token')
  if (!token) return c.text('Session Error', 403)
  
  let userId
  try {
    const payload = await verify(token, c.env.JWT_SECRET, 'HS256')
    userId = payload.sub as string
  } catch (e) { return c.text('Invalid Session', 403) }

  const body = await c.req.parseBody()
  const calendarId = body['calendar_id'] as string

  if (calendarId) {
    const supabase = createClient(c.env.SUPABASE_URL, c.env.SUPABASE_KEY)
    await supabase.from('users').update({ calendar_id: calendarId }).eq('line_user_id', userId)
  }
  return c.redirect('/settings')
})

// Update Action
app.post('/settings/update', async (c) => {
  const token = getCookie(c, 'auth_token')
  if (!token) return c.text('Session Error', 403)
  
  let userId
  try {
    const payload = await verify(token, c.env.JWT_SECRET, 'HS256')
    userId = payload.sub as string
  } catch (e) { return c.text('Invalid Session', 403) }

  const body = await c.req.parseBody()
  const action = body['action']
  const word = body['word']

  if (!word || typeof word !== 'string') return c.redirect('/settings')
  const safeWord = sanitizeText(word, 20)
  
  const supabase = createClient(c.env.SUPABASE_URL, c.env.SUPABASE_KEY)
  const { data } = await supabase.from('users').select('keywords').eq('line_user_id', userId).single()
  let current: string[] = data?.keywords || []

  if (action === 'add' && !current.includes(safeWord)) {
    current.push(safeWord)
  } else if (action === 'delete') {
    current = current.filter((k: string) => k !== safeWord)
  }

  await supabase.from('users').update({ keywords: current }).eq('line_user_id', userId)
  return c.redirect('/settings')
})


// --- Webhook ---

app.post('/webhook', async (c) => {
  const signature = c.req.header('x-line-signature')
  const rawBody = await c.req.text()
  
  if (!signature || !c.env.LINE_CHANNEL_SECRET) return c.text('Unauthorized', 401)
  
  const isValid = await verifyLineSignature(rawBody, signature, c.env.LINE_CHANNEL_SECRET)
  if (!isValid) return c.text('Unauthorized', 401)

  const body = JSON.parse(rawBody)
  // ログ出力のためにcatchを追加
  c.executionCtx.waitUntil(
      handleEvents(body.events, c.env, c.req.url)
        .catch(err => console.error('🚨 Global Error in handleEvents:', err))
  )
  return c.json({ message: 'ok' })
})

async function handleEvents(events: WebhookEvent[], env: Bindings, reqUrl: string) {
  const client = new messagingApi.MessagingApiClient({ channelAccessToken: env.LINE_CHANNEL_ACCESS_TOKEN })
  const supabase = createClient(env.SUPABASE_URL, env.SUPABASE_KEY)
  const allowedUsers = env.ALLOWED_USERS ? env.ALLOWED_USERS.split(',') : []
  const MODEL_NAME = 'gemini-2.0-flash'
  const baseUrl = new URL(reqUrl).origin
  
  for (const event of events) {
    // ---------------------------------------------------------
    // ■ Postback処理 (Undo / Rescue)
    // ---------------------------------------------------------
    if (event.type === 'postback') {
      const data = new URLSearchParams(event.postback.data)
      const action = data.get('action')
      const targetMsgId = data.get('msgId')
      const userId = event.source.userId
      
      if (!targetMsgId || !userId) continue

      // (解析実行ロジック) 
      if (action === 'analyze') {
         // 1. 二重処理防止
         const { error } = await supabase.from('processed_messages').insert({ message_id: targetMsgId })
         if (error) { 
            await client.replyMessage({ 
                replyToken: event.replyToken, 
                messages: [{ type: 'text', text: '⚠️ すでに解析済みか、エラーが発生しました' }] 
            })
            continue 
         }

         try {
             // ユーザー情報・認証取得
             const { data: userData } = await supabase.from('users').select('keywords, calendar_id').eq('line_user_id', userId).single()
             const { data: authData } = await supabase.from('google_auth').select('*').eq('user_id', userId).single()
             const userKeywords: string[] = userData?.keywords || []
             const targetCalendarId = userData?.calendar_id || 'primary'

             if (!authData) {
                const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 600 }
                const token = await sign(payload, env.JWT_SECRET, 'HS256')
                const lpUrl = `${baseUrl}/auth/landing?userId=${userId}`
                await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: `連携が必要です👇\n${lpUrl}` }] })
                continue
             }

             // 画像取得 (LINEサーバーから)
             const imgRes = await fetchWithRetry(`https://api-data.line.me/v2/bot/message/${targetMsgId}/content`, {
                 headers: { Authorization: `Bearer ${env.LINE_CHANNEL_ACCESS_TOKEN}` }
             })
             
             if (!imgRes.ok) throw new Error('画像が期限切れ等のため取得できませんでした')
             const imageBuffer = await imgRes.arrayBuffer()

             // Gemini API 呼び出し
             const genAI = new GoogleGenerativeAI(env.GEMINI_API_KEY)
             const model = genAI.getGenerativeModel({ model: MODEL_NAME, generationConfig: { responseMimeType: "application/json" } })
             
             const now = new Date()
             const jstNow = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Tokyo" }))
             
             // ★プロンプト (いただいた最新版をそのまま適用)
             const prompt = `あなたは学校プリント解析のプロ。JSON出力のみ。
             本日:${jstNow.toISOString().split('T')[0]} (YYYY-MM-DD)
             
             スキーマ: { "events": [{ "summary": string, "start": "YYYY-MM-DDTHH:mm:ss", "end": string?, "location": string?, "description": string?, "target": string? }] }
             
             抽出ルール:
             1. イベント: 行事予定のみ抽出。「給食の献立」「今月の目標」「校長先生の挨拶」はノイズとして無視。
             
             2. 日付 (誤認に注意): 
                - 「1年2組」「1-2」のような【学年・クラス表記】を日付(1月2日)と混同するな。これは日付ではない。
                - 月が明記されていない日付（例: "15日"）は、リストの並び順（時系列）を見て補完せよ。前の行より数字が小さくなった場合（例: 25日の次に3日が来た場合）のみ翌月と判断せよ。
                - 本日の月と比較し、イベント月が明らかに小さい場合（例: 本日が12月でイベントが1月）は翌年、それ以外は${jstNow.getFullYear()}年とする。
             
             3. 時間: 開始時刻不明なら "00:00:00"。「午前保育」等は description に記載。
             
             4. 対象(target) 【重要】: 
                - 「年少児保護者」のように学年指定がある場合は抽出。
                - その行事に関係する「学年」「クラス」を【カンマ区切り】で可能な限り列挙・展開せよ。
                - 表記は「X年Y組」「X年」に統一せよ（例: 「1-2」→「1年2組」）。
                - クラス行事であっても、親となる学年を含めよ（例: 「1年2組」なら "1年2組, 1年"）。
                - 範囲指定は展開せよ（例: 「1〜3年」なら "1年, 2年, 3年"）。
                - 「○月生まれ」「保護者」などの記述は学年指定ではないためターゲットに含めるな。学年指定がなければ空文字 (全員対象) とせよ。
             
             5. 場所・詳細: locationに場所、descriptionに持ち物や注意事項を記載。
             `

             const result = await model.generateContent([
                prompt,
                { inlineData: { data: Buffer.from(imageBuffer).toString('base64'), mimeType: "image/jpeg" } }
             ])
             
             let allEvents = []
             try {
               const cleanJson = extractJson(result.response.text())
               const json = JSON.parse(cleanJson)
               allEvents = ResponseSchema.parse(json).events
             } catch (e) {
               console.error('Parse Error:', e)
               await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: '読み取れませんでした💦' }] })
               continue
             }

             if (allEvents.length === 0) {
               await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: '予定が見つかりませんでした🙏' }] })
               continue
             }

             const keptEvents: any[] = []
             const ignoredEvents: any[] = []

             // ★正規化ロジック (いただいた最新版をそのまま適用)
             // キーワード正規化ヘルパー: "1-2" -> "12", "1年2組" -> "12" のように揺れを吸収
             const normalize = (str: string) => str.replace(/[０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0)) // 全角数字→半角
                                                   .replace(/[-－ー]/g, '') // ハイフン除去
                                                   .replace(/[年組生]/g, '') // 単位除去

             for (const ev of allEvents) {
               const safeTarget = sanitizeText(ev.target, 50)
       
               // 1. 「以外」「除く」が含まれていたら即除外
               if (safeTarget.includes('以外') || safeTarget.includes('除く')) {
                 ignoredEvents.push(ev)
                 continue 
               }
       
               // 2. 双方向チェック (親子関係・表記ゆれ対応)
               const isMatch = userKeywords.length > 0 && userKeywords.some(kw => {
                  // A. そのままの文字列で比較 (基本)
                  if (safeTarget.includes(kw) || (safeTarget.length > 0 && kw.includes(safeTarget))) return true
                  
                  // B. 正規化して比較 (救済策: "1-2" vs "1年2組" など)
                  const nKw = normalize(kw)
                  const nTarget = normalize(safeTarget)
                  
                  // 正規化後の文字数が少なすぎる場合（"1"だけ等）は誤爆防止のためチェックしない
                  if (nKw.length < 2 || nTarget.length < 2) return false
                  
                  return nTarget.includes(nKw) || nKw.includes(nTarget)
               })
       
               const isAll = !safeTarget || safeTarget.includes('全')
               const noSettings = userKeywords.length === 0
       
               if (isAll || noSettings || isMatch) {
                 keptEvents.push(ev)
               } else {
                 ignoredEvents.push(ev)
               }
             }

             // Googleトークンリフレッシュ
             let accessToken = authData.access_token
             if (Date.now() > (authData.expiry_date || 0)) {
                const newTokens = await (await fetchWithRetry('https://oauth2.googleapis.com/token', {
                  method: 'POST', 
                  headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                  body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: authData.refresh_token, grant_type: 'refresh_token' })
                })).json() as GoogleTokenResponse
                
                if (newTokens.error) throw new Error('Refresh Failed')
                accessToken = newTokens.access_token
                await supabase.from('google_auth').update({ access_token: accessToken, expiry_date: Date.now() + 3500 * 1000 }).eq('user_id', userId)
             }

             // カレンダー登録
             const calendarPromises = keptEvents.map(async (ev) => {
               const res = await fetchWithRetry(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(targetCalendarId)}/events`, {
                   method: 'POST',
                   headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
                   body: JSON.stringify({
                     summary: sanitizeText(ev.summary, 100),
                     location: sanitizeText(ev.location, 100),
                     description: sanitizeText(ev.description, 1000),
                     start: { dateTime: ev.start, timeZone: 'Asia/Tokyo' },
                     end: { dateTime: ev.end || ev.start, timeZone: 'Asia/Tokyo' }
                   })
               })
               const data = await res.json() as any
               if (data && data.id) {
                 return { ...ev, googleId: data.id }
               }
               return null
             })
      
             const results = await Promise.all(calendarPromises)
             const registeredEvents = results.filter((r): r is any => r !== null)

             // DB保存: Undo用
             if (registeredEvents.length > 0) {
               await supabase.from('calendar_events').insert(
                 registeredEvents.map(ev => ({
                   user_id: userId,
                   google_event_id: ev.googleId,
                   source_message_id: targetMsgId,
                   summary: ev.summary,
                   start_time: ev.start
                 }))
               )
             }
      
             // DB保存: Rescue用
             if (ignoredEvents.length > 0) {
               await supabase.from('parsing_logs').insert({
                 message_id: targetMsgId,
                 ignored_events: ignoredEvents
               })
             }

             if (registeredEvents.length === 0 && ignoredEvents.length === 0) {
               await client.replyMessage({
                 replyToken: event.replyToken,
                 messages: [{ type: 'text', text: '読み取れる予定がありませんでした🙏' }]
               })
               continue
             }

             const replyMessages = generateFlexMessages(registeredEvents, ignoredEvents, targetMsgId)
             await client.replyMessage({
                replyToken: event.replyToken,
                messages: replyMessages as any
             })

         } catch (e: any) {
             console.error(e)
             await client.replyMessage({ 
                 replyToken: event.replyToken, 
                 messages: [{ type: 'text', text: `エラーが発生しました: ${e.message}` }] 
             })
         }
      }

      // Undo機能 (削除)
      if (action === 'undo') {
        const { data: eventsToDelete } = await supabase
          .from('calendar_events')
          .select('*')
          .eq('source_message_id', targetMsgId)
          .eq('user_id', userId)
        
        if (!eventsToDelete || eventsToDelete.length === 0) {
          await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: '削除できるデータが見つかりませんでした。' }] })
          continue
        }

        const { data: authData } = await supabase.from('google_auth').select('*').eq('user_id', userId).single()
        let accessToken = authData?.access_token
        
        if (authData && Date.now() > (authData.expiry_date || 0)) {
           const newTokens = await (await fetchWithRetry('https://oauth2.googleapis.com/token', {
              method: 'POST', 
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: authData.refresh_token, grant_type: 'refresh_token' })
           })).json() as GoogleTokenResponse
           accessToken = newTokens.access_token
           await supabase.from('google_auth').update({ access_token: accessToken, expiry_date: Date.now() + 3500 * 1000 }).eq('user_id', userId)
        }

        const { data: userDataForUndo } = await supabase.from('users').select('calendar_id').eq('line_user_id', userId).single()
        const calendarIdForUndo = userDataForUndo?.calendar_id || 'primary'

        let deletedCount = 0
        for (const ev of eventsToDelete) {
          const res = await fetchWithRetry(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(calendarIdForUndo)}/events/${ev.google_event_id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${accessToken}` }
          })
          if (res.ok || res.status === 404) deletedCount++
        }

        await supabase.from('calendar_events').delete().eq('source_message_id', targetMsgId)
        await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: `🗑️ ${deletedCount}件を取り消しました。` }] })
      }

      // Rescue機能 (救出)
      if (action === 'rescue') {
        const { data: logData } = await supabase.from('parsing_logs').select('ignored_events').eq('message_id', targetMsgId).single()
        const ignoredEvents = logData?.ignored_events as any[]
        
        if (!ignoredEvents || ignoredEvents.length === 0) {
          await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: '救出できる予定が見つかりませんでした。' }] })
          continue
        }

        // await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: `🚑 ${ignoredEvents.length}件を救出中...` }] })

        const { data: authData } = await supabase.from('google_auth').select('*').eq('user_id', userId).single()
        let accessToken = authData?.access_token
        if (authData && Date.now() > (authData.expiry_date || 0)) {
           const newTokens = await (await fetchWithRetry('https://oauth2.googleapis.com/token', {
              method: 'POST', 
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: authData.refresh_token, grant_type: 'refresh_token' })
           })).json() as GoogleTokenResponse
           accessToken = newTokens.access_token
           await supabase.from('google_auth').update({ access_token: accessToken, expiry_date: Date.now() + 3500 * 1000 }).eq('user_id', userId)
        }

        const { data: userDataForRescue } = await supabase.from('users').select('calendar_id').eq('line_user_id', userId).single()
        const targetCalendarId = userDataForRescue?.calendar_id || 'primary'

        const rescuePromises = ignoredEvents.map(async (ev) => {
          const res = await fetchWithRetry(`https://www.googleapis.com/calendar/v3/calendars/${encodeURIComponent(targetCalendarId)}/events`, {
              method: 'POST',
              headers: { Authorization: `Bearer ${accessToken}`, 'Content-Type': 'application/json' },
              body: JSON.stringify({
                summary: sanitizeText(ev.summary, 100),
                location: sanitizeText(ev.location, 100),
                description: sanitizeText(ev.description, 1000) + '\n(救出された予定)',
                start: { dateTime: ev.start, timeZone: 'Asia/Tokyo' },
                end: { dateTime: ev.end || ev.start, timeZone: 'Asia/Tokyo' }
              })
          })
          const data = await res.json() as any
          if (data && data.id) return { ...ev, googleId: data.id }
          return null
        })

        const results = await Promise.all(rescuePromises)
        const rescued = results.filter((r): r is any => r !== null)

        if (rescued.length > 0) {
          await supabase.from('calendar_events').insert(
            rescued.map(ev => ({
              user_id: userId,
              google_event_id: ev.googleId,
              source_message_id: targetMsgId,
              summary: ev.summary,
              start_time: ev.start
            }))
          )
          await supabase.from('parsing_logs').delete().eq('message_id', targetMsgId)
        }

        const rescueMessages = generateFlexMessages(rescued, [], targetMsgId)
        await client.replyMessage({ 
          replyToken: event.replyToken, 
          // 念のため as any
          messages: rescueMessages as any
        })
      }
      continue
    }

    // ---------------------------------------------------------
    // ■ テキストメッセージ処理 (特定キーワードのみ反応)
    // ---------------------------------------------------------
    if (event.type === 'message' && event.message.type === 'text') {
       const rawText = event.message.text
       const liffUrl = `https://liff.line.me/${env.LINE_LIFF_ID}`

       // 1. 表記ゆれを吸収する正規化（全角英数→半角、大文字→小文字、空白除去）
       // 例: "Ｈｅｌｐ " -> "help", " 設定" -> "設定"
       const text = rawText.trim()
         .replace(/[Ａ-Ｚａ-ｚ０-９]/g, s => String.fromCharCode(s.charCodeAt(0) - 0xFEE0))
         .toLowerCase()

       // 2. 設定コマンド (設定, setting 等)
       if (text === '設定' || text === 'setting') {
         const settingsMsg = createSettingsBubble(liffUrl)
         await client.replyMessage({
           replyToken: event.replyToken,
           messages: [{ type: 'flex', altText: '⚙️ プリカレ設定', contents: settingsMsg }]
         })
       } 
       // 3. ヘルプコマンド (使い方, ヘルプ, help 等)
       else if (['使い方', 'ヘルプ', 'help', 'ガイド'].includes(text)) {
         const helpMsg = createHelpBubble(liffUrl)
         await client.replyMessage({
           replyToken: event.replyToken,
           messages: [{ type: 'flex', altText: '🔰 プリカレの使い方', contents: helpMsg }]
         })
       }
       
       // 4. それ以外の会話は完全スルー (グループでの誤爆防止)
       continue
    }

    // ---------------------------------------------------------
    // ■ 画像処理フロー（コスト削減版）
    // ---------------------------------------------------------
    if (event.type === 'message' && event.message.type === 'image') {
       const messageId = event.message.id
       
       // 確認バブルを作成
       const confirmMsg = createConfirmBubble(messageId)
       
       // 無料の ReplyMessage でボタンを送る
       await client.replyMessage({
         replyToken: event.replyToken,
         messages: [{ type: 'flex', altText: '📷 画像を確認しました', contents: confirmMsg as any }]
       })
       continue
    }
  }
}

export default app