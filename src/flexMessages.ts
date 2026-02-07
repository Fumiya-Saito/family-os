import { FlexContainer, FlexBubble } from '@line/bot-sdk'

// 1. 個別のイベント用カード (青いヘッダー)
function createEventBubble(ev: any): FlexBubble {
  const dateStr = ev.start.slice(5, 10).replace('-', '/')
  const timeStr = ev.start.includes('T') && ev.start.length > 10 ? ev.start.slice(11, 16) : ''
  
  return {
    type: 'bubble',
    size: 'micro',
    header: {
      type: 'box',
      layout: 'vertical',
      contents: [
        { type: 'text', text: timeStr ? `${dateStr} ${timeStr}` : dateStr, weight: 'bold', color: '#FFFFFF', size: 'sm' }
      ],
      backgroundColor: '#0367D3', // Google Calendar Blue
      paddingTop: '6px',
      paddingBottom: '6px'
    },
    body: {
      type: 'box',
      layout: 'vertical',
      contents: [
        { type: 'text', text: ev.summary || 'タイトルなし', weight: 'bold', size: 'md', wrap: true },
        { type: 'text', text: ev.location || '場所指定なし', size: 'xs', color: '#888888', margin: 'sm', wrap: true }
      ],
      paddingTop: '10px',
      paddingBottom: '10px'
    },
    footer: {
      type: 'box',
      layout: 'vertical',
      contents: [
        {
          type: 'button',
          style: 'link',
          height: 'sm',
          action: { type: 'uri', label: 'カレンダーで見る', uri: 'https://calendar.google.com/calendar/' }
        }
      ]
    }
  }
}

// 2. 結果まとめ＆操作用カード (グレーのヘッダー)
function createSummaryBubble(successCount: number, ignoredEvents: any[], messageId: string): FlexBubble {
  const ignoredList = ignoredEvents.slice(0, 3).map(ev => ({
    type: 'text' as const,
    text: `・${ev.summary} (${ev.target || '不明'})`,
    size: 'xxs',
    color: '#aaaaaa',
    wrap: true
  }))

  return {
    type: 'bubble',
    size: 'kilo',
    header: {
      type: 'box',
      layout: 'vertical',
      contents: [{ type: 'text', text: '📊 完了レポート', weight: 'bold', color: '#666666', size: 'sm' }],
      backgroundColor: '#f0f0f0'
    },
    body: {
      type: 'box',
      layout: 'vertical',
      contents: [
        {
          type: 'box',
          layout: 'horizontal',
          contents: [
            { type: 'text', text: `✅ 登録: ${successCount}件`, size: 'sm', weight: 'bold', flex: 1 },
            { type: 'text', text: `🗑️ 除外: ${ignoredEvents.length}件`, size: 'sm', color: '#888888', flex: 1 }
          ]
        },
        { type: 'separator', margin: 'md' },
        ...(ignoredEvents.length > 0 ? [
            { type: 'text' as const, text: '除外された予定:', margin: 'md', size: 'xs', weight: 'bold' },
            ...ignoredList,
            (ignoredEvents.length > 3 ? { type: 'text' as const, text: '...他', size: 'xxs', color: '#aaaaaa' } : { type: 'filler' as const })
        ] : []),
        { type: 'separator', margin: 'md' },
        { type: 'text', text: '間違いがありましたか？', margin: 'md', size: 'xs', align: 'center', color: '#aaaaaa' }
      ]
    },
    footer: {
      type: 'box',
      layout: 'vertical',
      contents: [
        // Undoボタン: ここで「取り消し」のアクションを発火
        {
          type: 'button',
          style: 'secondary',
          color: '#ff3333',
          action: {
            type: 'postback',
            label: '今回の登録を取り消す',
            data: `action=undo&msgId=${messageId}`,
            displayText: '今回の登録を全て取り消します'
          }
        }
      ],
      spacing: 'sm'
    }
  }
}

// 3. メイン生成関数
export function generateResultFlex(keptEvents: any[], ignoredEvents: any[], messageId: string): FlexContainer {
  // イベントカードを生成
  const bubbles: FlexBubble[] = keptEvents.map(ev => createEventBubble(ev))
  // 最後にまとめカードを追加
  bubbles.push(createSummaryBubble(keptEvents.length, ignoredEvents, messageId))

  return {
    type: 'carousel',
    contents: bubbles
  }
}