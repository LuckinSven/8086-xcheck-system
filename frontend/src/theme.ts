export const THEME_STORAGE_KEY = 'xcheck-theme'

export const themes = [
  {
    id: 'threatbook-red',
    name: '微步社区红',
    description: '情报红与深酒红，微步社区风格',
    swatches: ['#c9252d', '#31171b', '#f8f4f4'],
  },
  {
    id: 'intelligence-blue',
    name: '情报蓝',
    description: '原有深海军蓝与明亮情报蓝',
    swatches: ['#1769e0', '#071a33', '#f4f7fb'],
  },
  {
    id: 'eye-care',
    name: '护眼青绿',
    description: '低饱和青绿与柔和暖白',
    swatches: ['#3f725e', '#20362f', '#f2f6ef'],
  },
  {
    id: 'midnight-violet',
    name: '暗夜紫',
    description: '沉静深紫与清晰蓝紫',
    swatches: ['#5f50cb', '#17132b', '#f6f4fb'],
  },
  {
    id: 'amber-sand',
    name: '琥珀沙金',
    description: '温暖琥珀与低调沙色',
    swatches: ['#9e5f18', '#2d2317', '#f7f2e9'],
  },
  {
    id: 'ocean-mist',
    name: '雾海青蓝',
    description: '清爽海蓝与轻盈雾白',
    swatches: ['#0f7186', '#0d2a33', '#eef6f7'],
  },
] as const

export type ThemeId = typeof themes[number]['id']
type StorageReader = Pick<Storage, 'getItem'>
type StorageWriter = Pick<Storage, 'setItem'>

export const DEFAULT_THEME_ID: ThemeId = 'threatbook-red'

function isThemeId(value: string | null): value is ThemeId {
  return themes.some((theme) => theme.id === value)
}

export function readStoredTheme(storage?: StorageReader): ThemeId {
  try {
    const stored = (storage ?? window.localStorage).getItem(THEME_STORAGE_KEY)
    return isThemeId(stored) ? stored : DEFAULT_THEME_ID
  } catch {
    return DEFAULT_THEME_ID
  }
}

export function applyTheme(themeId: ThemeId, root: HTMLElement = document.documentElement) {
  root.dataset.theme = themeId
}

export function persistTheme(themeId: ThemeId, storage?: StorageWriter) {
  try {
    const activeStorage = storage ?? window.localStorage
    activeStorage.setItem(THEME_STORAGE_KEY, themeId)
  } catch {
    // A blocked local-storage policy must not prevent in-session theme changes.
  }
}
