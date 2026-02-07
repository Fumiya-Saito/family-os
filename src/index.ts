import { Hono } from 'hono'
import { getCookie, setCookie } from 'hono/cookie'
import { csrf } from 'hono/csrf'
import { createClient } from '@supabase/supabase-js'
import { GoogleGenerativeAI } from '@google/generative-ai'
import { messagingApi, WebhookEvent } from '@line/bot-sdk'
import { z } from 'zod'
import { sign, verify } from 'hono/jwt'
import { generateResultFlex } from './flexMessages'

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
  start: z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, "Invalid date format"),
  end: z.string().optional(),
  location: z.string().optional(),
  description: z.string().optional(),
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
    scope: 'https://www.googleapis.com/auth/calendar.events',
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


// --- Settings UI ---

// Entry Page
app.get('/settings/entry', async (c) => {
  const token = c.req.query('token')
  if (!token) return c.text('Error', 403)
  
  return c.html(`
    <!DOCTYPE html>
    <html lang="ja">
      <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>フィルタ設定</title>
        <meta name="description" content="タップして設定画面を開きます">
        <style>
          body{display:flex;justify-content:center;align-items:center;height:100vh;background:#f0f0f0;font-family:sans-serif;color:#666;}
          .loader {border: 4px solid #f3f3f3;border-top: 4px solid #3498db;border-radius: 50%;width: 30px;height: 30px;animation: spin 1s linear infinite;margin-bottom:10px;}
          @keyframes spin {0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); }}
          div{text-align:center;}
        </style>
        <script>window.onload = function() { document.getElementById('loginForm').submit(); }</script>
      </head>
      <body>
        <div>
          <div class="loader" style="margin:0 auto;"></div>
          <p>設定画面へ移動中...</p>
          <form id="loginForm" action="/settings/login" method="POST">
            <input type="hidden" name="token" value="${token}">
          </form>
        </div>
      </body>
    </html>
  `)
})

// Login Action
app.post('/settings/login', async (c) => {
  const body = await c.req.parseBody()
  const token = body['token'] as string
  if (!token) return c.text('Invalid Request', 400)

  try {
    await verify(token, c.env.JWT_SECRET, 'HS256')
    const isSecure = c.env.ENVIRONMENT !== 'local'
    setCookie(c, 'auth_token', token, { httpOnly: true, secure: isSecure, path: '/', maxAge: 3600, sameSite: 'Lax' })
    return c.redirect('/settings')
  } catch (e) { return c.text('Invalid or Expired Token', 403) }
})

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
  const { data } = await supabase.from('users').select('keywords').eq('line_user_id', userId).single()
  const keywords: string[] = data?.keywords || []

  return c.html(`
    <!DOCTYPE html>
    <html lang="ja">
      <head>
        <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
        <title>フィルタ設定</title>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@picocss/pico@1/css/pico.min.css">
        <style>.tag{display:inline-block;background:#eee;color:#333;padding:4px 8px;border-radius:4px;margin:2px;} button.del{border:none;background:none;color:red;cursor:pointer;padding:0 5px;}</style>
      </head>
      <body style="padding:1rem;max-width:600px;margin:0 auto;">
        <main>
          <h3>⚙️ 学年・クラスのフィルタ設定</h3>
          <p>
            ここに追加したキーワード（学年やクラス名）が含まれる予定を<br>
            <strong>「抽出」</strong>してカレンダーに登録します。<br>
            <small>※何も設定しない場合は、全ての予定が登録されます。</small>
          </p>
          <article>
            <div>
              ${keywords.length === 0 ? '<small>設定なし（全件登録）</small>' : ''}
              ${keywords.map((k: string) => `
                <span class="tag">${sanitizeText(k, 20)}
                  <form action="/settings/update" method="POST" style="display:inline">
                    <input type="hidden" name="action" value="delete">
                    <input type="hidden" name="word" value="${sanitizeText(k)}">
                    <button type="submit" class="del">×</button>
                  </form>
                </span>
              `).join('')}
            </div>
          </article>
          <article>
            <form action="/settings/update" method="POST">
              <input type="hidden" name="action" value="add">
              <label>追加<input type="text" name="word" placeholder="例: 年長" required maxlength="20"></label>
              <button type="submit">追加</button>
            </form>
          </article>
        </main>
      </body>
    </html>
  `)
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
  c.executionCtx.waitUntil(handleEvents(body.events, c.env, c.req.url))
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
    // ■ Undo機能 (Postback処理)
    // ---------------------------------------------------------
    if (event.type === 'postback') {
      const data = new URLSearchParams(event.postback.data)
      const action = data.get('action')
      const targetMsgId = data.get('msgId')
      const userId = event.source.userId
      
      if (action === 'undo' && targetMsgId && userId) {
        // 1. DBから削除対象のイベントを取得
        const { data: eventsToDelete } = await supabase
          .from('calendar_events')
          .select('*')
          .eq('source_message_id', targetMsgId)
          .eq('user_id', userId)
        
        if (!eventsToDelete || eventsToDelete.length === 0) {
          await client.replyMessage({ replyToken: event.replyToken, messages: [{ type: 'text', text: '削除できるデータが見つかりませんでした（既に削除済みかもしれません）。' }] })
          continue
        }

        // 2. Google Calendarから削除 (認証トークン取得)
        const { data: authData } = await supabase.from('google_auth').select('*').eq('user_id', userId).single()
        let accessToken = authData?.access_token
        
        // トークンリフレッシュ処理 (必要な場合)
        if (authData && Date.now() > (authData.expiry_date || 0)) {
           const newTokens = await (await fetchWithRetry('https://oauth2.googleapis.com/token', {
              method: 'POST', 
              headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
              body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: authData.refresh_token, grant_type: 'refresh_token' })
           })).json() as GoogleTokenResponse
           accessToken = newTokens.access_token
           await supabase.from('google_auth').update({ access_token: accessToken, expiry_date: Date.now() + 3500 * 1000 }).eq('user_id', userId)
        }

        // 削除実行
        let deletedCount = 0
        for (const ev of eventsToDelete) {
          const res = await fetchWithRetry(`https://www.googleapis.com/calendar/v3/calendars/primary/events/${ev.google_event_id}`, {
            method: 'DELETE',
            headers: { Authorization: `Bearer ${accessToken}` }
          })
          if (res.ok || res.status === 404) deletedCount++ // 404は既に消えているので成功扱い
        }

        // 3. DBから削除
        await supabase.from('calendar_events').delete().eq('source_message_id', targetMsgId)

        await client.replyMessage({ 
          replyToken: event.replyToken, 
          messages: [{ type: 'text', text: `🗑️ ${deletedCount}件の予定を取り消しました。元に戻りました！` }] 
        })
      }
      continue
    }

    // ---------------------------------------------------------
    // ■ 通常の画像処理フロー
    // ---------------------------------------------------------
    if (event.type === 'message' && event.message.type === 'text') {
       if (event.message.text.includes('設定')) {
         const userId = event.source.userId
         if(!userId) continue
         const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 3600 }
         const token = await sign(payload, env.JWT_SECRET, 'HS256')
         const entryUrl = `${baseUrl}/settings/entry?token=${token}`
         await client.replyMessage({
           replyToken: event.replyToken,
           messages: [{ type: 'text', text: `⚙️ 学年・クラスのフィルタ設定:\n${entryUrl}\n(リンクは1時間有効)` }]
         })
       }
       continue
    }

    if (event.type !== 'message' || event.message.type !== 'image') continue
    const userId = event.source.userId
    if (!userId) continue 

    const messageId = event.message.id
    const { error } = await supabase.from('processed_messages').insert({ message_id: messageId })
    if (error) { console.log(`Duplicate`); continue }

    const replyToken = event.replyToken
    if (allowedUsers.length > 0 && !allowedUsers.includes(userId)) return

    try {
      const { data: userData } = await supabase.from('users').select('keywords').eq('line_user_id', userId).single()
      const { data: authData } = await supabase.from('google_auth').select('*').eq('user_id', userId).single()
      const userKeywords: string[] = userData?.keywords || []

      if (!authData) {
        const payload = { sub: userId, exp: Math.floor(Date.now() / 1000) + 600 }
        const token = await sign(payload, env.JWT_SECRET, 'HS256')
        const lpUrl = `${baseUrl}/auth/landing?userId=${userId}`
        await client.replyMessage({ replyToken, messages: [{ type: 'text', text: `連携が必要です👇\n${lpUrl}` }] })
        return
      }

      await client.replyMessage({ replyToken, messages: [{ type: 'text', text: '解析中...📸' }] })

      const imgRes = await fetchWithRetry(`https://api-data.line.me/v2/bot/message/${messageId}/content`, {
          headers: { Authorization: `Bearer ${env.LINE_CHANNEL_ACCESS_TOKEN}` }
      })
      const imageBuffer = await imgRes.arrayBuffer()

      const genAI = new GoogleGenerativeAI(env.GEMINI_API_KEY)
      const model = genAI.getGenerativeModel({ model: MODEL_NAME, generationConfig: { responseMimeType: "application/json" } })
      
      const now = new Date()
      const jstNow = new Date(now.toLocaleString("en-US", { timeZone: "Asia/Tokyo" }))
      
      const prompt = `あなたは学校プリント解析のプロ。JSON出力のみ。
      本日:${jstNow.toISOString().split('T')[0]} (YYYY-MM-DD)
      
      スキーマ: { "events": [{ "summary": string, "start": "YYYY-MM-DDTHH:mm:ss", "end": string?, "location": string?, "description": string?, "target": string? }] }
      
      抽出ルール:
      1. イベント: 行事予定のみ抽出。「給食の献立」「今月の目標」「校長先生の挨拶」はノイズとして無視。
      2. 日付: 本日の月と比較し、イベント月が明らかに小さい場合（例: 本日が12月でイベントが1月）は、翌年として処理せよ。それ以外は${jstNow.getFullYear()}年とする。
      3. 時間: 開始時刻不明なら "00:00:00"。「午前保育」等は description に記載。
      4. 対象(target): 
         - 「年少児保護者」のように学年指定がある場合は "年少" のように抽出。
         - 学年指定がなく「○月生まれ」「保護者」のみの場合は null (全員対象) とする。
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
        await client.pushMessage({ to: userId, messages: [{ type: 'text', text: '読み取れませんでした💦' }] })
        return
      }

      if (allEvents.length === 0) {
        await client.pushMessage({ to: userId, messages: [{ type: 'text', text: '予定が見つかりませんでした🙏' }] })
        return
      }

      const keptEvents: any[] = []
      const ignoredEvents: any[] = []

      for (const ev of allEvents) {
        const safeTarget = sanitizeText(ev.target, 50)
        const isMatch = userKeywords.length > 0 && userKeywords.some(kw => safeTarget.includes(kw))
        const isAll = !safeTarget || safeTarget.includes('全')
        const noSettings = userKeywords.length === 0

        if (isAll || noSettings || isMatch) {
          keptEvents.push(ev)
        } else {
          ignoredEvents.push(ev)
        }
      }

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

      // -------------------------------------------------------
      // ★修正: Google Calendar登録 & ID取得
      // -------------------------------------------------------
      
      // バッチではなく1件ずつ登録して確実にIDを取得する (並列処理)
      const calendarPromises = keptEvents.map(async (ev) => {
        const res = await fetchWithRetry('https://www.googleapis.com/calendar/v3/calendars/primary/events', {
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
        
        // ★修正点: 'as any' を追加して型エラーを回避
        const data = await res.json() as any 
        
        if (data && data.id) {
          return { ...ev, googleId: data.id } // 成功したらID付きで返す
        }
        return null
      })

      const results = await Promise.all(calendarPromises)
      // nullを除外して、成功したイベントだけ抽出
      const registeredEvents = results.filter((r): r is any => r !== null)

      // -------------------------------------------------------
      // ★修正: DBへの保存 (Undo機能用)
      // -------------------------------------------------------
      if (registeredEvents.length > 0) {
        const { error: dbError } = await supabase.from('calendar_events').insert(
          registeredEvents.map(ev => ({
            user_id: userId,
            google_event_id: ev.googleId,
            source_message_id: messageId,
            summary: ev.summary,
            start_time: ev.start
          }))
        )
        if (dbError) console.error('DB Insert Error:', dbError)
      }

      // -------------------------------------------------------
      // ★修正: Flex Message 送信
      // -------------------------------------------------------
      const flexMsg = generateResultFlex(registeredEvents, ignoredEvents, messageId)
      
      await client.pushMessage({
        to: userId,
        messages: [{ type: 'flex', altText: `📅 ${registeredEvents.length}件の予定を登録しました`, contents: flexMsg }]
      })

    } catch (e: any) {
      console.error(e)
      await client.pushMessage({ to: userId, messages: [{ type: 'text', text: `エラーが発生しました: ${e.message}` }] })
    }
  }
}

export default app