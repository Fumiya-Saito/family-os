import { FlexBubble, FlexComponent, Message, FlexBox } from '@line/bot-sdk'

// 文字数制限ヘルパー
const safeStr = (str: string | any, max: number) => {
  if (!str) return ''
  const s = String(str)
  return s.replace(/[\r\n]+/g, ' ').trim().slice(0, max)
}

// 日付フォーマットヘルパー (例: 02/09 10:00)
const formatDate = (isoStart: string) => {
  if (!isoStart) return '不明'
  const datePart = isoStart.slice(5, 10).replace('-', '/')
  const timePart = (isoStart.includes('T') && isoStart.length > 10) ? isoStart.slice(11, 16) : ''
  // 時間が00:00なら日付だけ、それ以外は時間も表示
  return timePart === '00:00' ? datePart : (timePart ? `${datePart} ${timePart}` : datePart)
}

// 1. 【新設】登録された予定の一覧リスト (横スクロール廃止)
function createRegisteredListBubble(events: any[]): FlexBubble {
  // 表示件数制限 (最大10件まで表示)
  const MAX_DISPLAY = 10
  const displayEvents = events.slice(0, MAX_DISPLAY)
  const remaining = events.length - MAX_DISPLAY

  // リストの行を作成
  const eventRows: FlexComponent[] = displayEvents.map(ev => {
    return {
      type: 'box',
      layout: 'baseline',
      spacing: 'sm',
      contents: [
        {
          type: 'text',
          text: formatDate(ev.start),
          color: '#0367D3', // リンクっぽい青色で強調
          size: 'sm',
          flex: 2,
          weight: 'bold'
        },
        {
          type: 'text',
          text: safeStr(ev.summary, 20),
          color: '#333333',
          size: 'sm',
          flex: 5,
          wrap: true
        }
      ]
    }
  })

  // 「...他 N件」の表示
  if (remaining > 0) {
    eventRows.push({
      type: 'text',
      text: `...他 ${remaining}件`,
      size: 'xs',
      color: '#aaaaaa',
      align: 'end',
      margin: 'md'
    })
  }

  return {
    type: 'bubble',
    size: 'kilo',
    header: {
      type: 'box',
      layout: 'vertical',
      contents: [
        { type: 'text', text: `📅 登録リスト (${events.length}件)`, weight: 'bold', color: '#0367D3' }
      ],
      backgroundColor: '#eef5ff'
    },
    body: {
      type: 'box',
      layout: 'vertical',
      contents: [
        ...eventRows,
        { type: 'separator', margin: 'lg' },
        {
           type: 'text',
           text: '※修正はGoogleカレンダーで行ってください',
           size: 'xxs',
           color: '#aaaaaa',
           margin: 'md',
           align: 'center'
        }
      ],
      spacing: 'xs'
    },
    footer: {
      type: 'box',
      layout: 'vertical',
      contents: [
        {
          type: 'button',
          style: 'link',
          height: 'sm',
          action: {
            type: 'uri',
            label: 'Googleカレンダーを開く',
            uri: 'https://calendar.google.com/calendar/'
          }
        }
      ]
    }
  }
}

// 2. 結果まとめ用カード (除外レポート)
function createSummaryBubble(successCount: number, ignoredEvents: any[], messageId: string): FlexBubble {
  // 除外リストも多めに表示 (最大10件)
  const MAX_DISPLAY = 10
  
  const ignoredTextList = ignoredEvents.slice(0, MAX_DISPLAY)
    .map(ev => `・${safeStr(ev.summary, 20)}`)
    .join('\n')
  
  const moreText = ignoredEvents.length > MAX_DISPLAY 
    ? `\n...他 ${ignoredEvents.length - MAX_DISPLAY}件` 
    : ''
    
  const finalIgnoredText = ignoredTextList + moreText

  const bodyContents: FlexComponent[] = []

  // 成功数・除外数のヘッダー
  bodyContents.push({
    type: 'box',
    layout: 'horizontal',
    contents: [
      { type: 'text', text: `✅ 登録: ${successCount}件`, weight: 'bold', flex: 1 },
      { type: 'text', text: `🗑️ 除外: ${ignoredEvents.length}件`, color: '#888888', flex: 1 }
    ]
  })

  // 除外リスト本体
  if (ignoredEvents.length > 0) {
    bodyContents.push({ type: 'separator' }) 
    bodyContents.push({ type: 'text', text: '▼除外された予定', weight: 'bold', color: '#aaaaaa', wrap: true })
    bodyContents.push({ type: 'text', text: finalIgnoredText, color: '#aaaaaa', wrap: true, size: 'xs' })
  }

  bodyContents.push({ type: 'separator' })
  bodyContents.push({ type: 'text', text: '間違いがありましたか？', align: 'center', color: '#aaaaaa', size: 'xs' })

  // フッターボタン
  const footerContents: FlexComponent[] = [
    {
      type: 'button',
      style: 'secondary',
      color: '#ff3333',
      height: 'sm',
      action: {
        type: 'postback',
        label: '取り消す',
        data: `action=undo&msgId=${messageId}`,
        displayText: '今回の登録を取り消します'
      }
    }
  ]

  // ★ここを変更: 「救出する」→「これも登録する」
  if (ignoredEvents.length > 0) {
    footerContents.push({
      type: 'button',
      style: 'link',
      height: 'sm',
      action: {
        type: 'postback',
        label: 'これも登録する', // ★分かりやすさ重視に変更
        data: `action=rescue&msgId=${messageId}`,
        displayText: '除外された予定も追加で登録します'
      }
    })
  }

  return {
    type: 'bubble',
    size: 'kilo',
    header: {
      type: 'box',
      layout: 'vertical',
      contents: [{ type: 'text', text: '📊 完了レポート', weight: 'bold', color: '#666666' }],
      backgroundColor: '#f0f0f0'
    },
    body: {
      type: 'box',
      layout: 'vertical',
      contents: bodyContents,
      spacing: 'md'
    },
    footer: {
      type: 'box',
      layout: 'vertical',
      contents: footerContents,
      spacing: 'sm'
    }
  }
}

// 3. メイン生成関数
export function generateFlexMessages(keptEvents: any[], ignoredEvents: any[], messageId: string): Message[] {
  const messages: Message[] = []

  // 1通目: 登録リスト (Bubble)
  if (keptEvents.length > 0) {
    const listBubble = createRegisteredListBubble(keptEvents)
    messages.push({
      type: 'flex',
      altText: `📅 ${keptEvents.length}件の予定`,
      contents: listBubble
    })
  }

  // 2通目: 完了レポート (Bubble)
  // イベントが0件でも、除外があればレポートは出す
  if (keptEvents.length > 0 || ignoredEvents.length > 0) {
    const summaryBubble = createSummaryBubble(keptEvents.length, ignoredEvents, messageId)
    messages.push({
      type: 'flex',
      altText: '📊 完了レポート',
      contents: summaryBubble
    })
  }

  return messages
}

// 4. 【新設】解析開始の確認用バブル
export function createConfirmBubble(messageId: string): FlexBubble {
  return {
    type: 'bubble',
    size: 'kilo',
    body: {
      type: 'box',
      layout: 'vertical',
      contents: [
        {
          type: 'text',
          text: '📷 画像を受け取りました',
          weight: 'bold',
          size: 'md',
          color: '#1DB446'
        },
        {
          type: 'text',
          text: '学校プリントの解析を開始しますか？\n（関係ない画像の場合は無視してください）',
          size: 'xs',
          color: '#aaaaaa',
          wrap: true,
          margin: 'md'
        }
      ]
    },
    footer: {
      type: 'box',
      layout: 'vertical',
      contents: [
        {
          type: 'button',
          style: 'primary',
          height: 'sm',
          action: {
            type: 'postback',
            label: '解析する',
            data: `action=analyze&msgId=${messageId}`, // ここで画像のIDを引き継ぐ
            displayText: '解析を開始します'
          }
        }
      ]
    }
  }
}