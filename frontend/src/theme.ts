export const themes = [
  {
    id: 'threatbook-red',
    swatches: ['#c9252d', '#31171b', '#f8f4f4'],
  },
  {
    id: 'intelligence-blue',
    swatches: ['#1769e0', '#071a33', '#f4f7fb'],
  },
  {
    id: 'eye-care',
    swatches: ['#3f725e', '#20362f', '#f2f6ef'],
  },
  {
    id: 'midnight-violet',
    swatches: ['#5f50cb', '#17132b', '#f6f4fb'],
  },
  {
    id: 'amber-sand',
    swatches: ['#9e5f18', '#2d2317', '#f7f2e9'],
  },
  {
    id: 'ocean-mist',
    swatches: ['#0f7186', '#0d2a33', '#eef6f7'],
  },
] as const

export type ThemeId = typeof themes[number]['id']

export const DEFAULT_THEME_ID: ThemeId = 'threatbook-red'

export function applyTheme(themeId: ThemeId, root: HTMLElement = document.documentElement) {
  root.dataset.theme = themeId
}
