<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'

import type { LandscapeDashboard, RankedDashboardItem } from '../../types'
import DashboardSparkline from './DashboardSparkline.vue'

const props = defineProps<{ dashboard: LandscapeDashboard }>()
const { t, n } = useI18n()

const knownPoints: Record<string, [number, number]> = {
  China: [148, 58], 'United States': [48, 56], USA: [48, 56], Russia: [128, 35],
  Germany: [103, 48], France: [98, 51], India: [135, 68], Japan: [168, 57],
  Brazil: [72, 88], Australia: [164, 96], Canada: [48, 31], 'United Kingdom': [94, 43],
}

function fallbackPoint(name: string): [number, number] {
  const hash = [...name].reduce((value, character) => value + character.charCodeAt(0), 0)
  return [24 + (hash * 19) % 150, 28 + (hash * 7) % 70]
}

const markers = computed(() => {
  const maximum = Math.max(...props.dashboard.sections.countries.items.map((item) => item.count), 1)
  return props.dashboard.sections.countries.items.map((item) => ({
    ...item,
    point: knownPoints[item.name] || fallbackPoint(item.name),
    radius: 3 + Math.sqrt(item.count / maximum) * 5,
  }))
})

function width(item: RankedDashboardItem, items: RankedDashboardItem[]) {
  return `${Math.max(8, item.count * 100 / Math.max(...items.map((entry) => entry.count), 1))}%`
}
</script>

<template>
  <div class="dashboard-layout landscape-layout" data-dashboard="landscape">
    <section class="dashboard-metrics landscape-metrics">
      <article class="risk-metric"><span>{{ t('dashboard.metrics.malicious24h') }}</span><b>{{ n(dashboard.summary.malicious_last_24h) }}</b><i>24H</i></article>
      <article><span>{{ t('dashboard.metrics.totalMalicious') }}</span><b>{{ n(dashboard.summary.total_malicious) }}</b><i>ALL</i></article>
      <article><span>{{ t('dashboard.metrics.affectedCountries') }}</span><b>{{ n(dashboard.summary.affected_countries) }}</b><i>GEO</i></article>
    </section>

    <section class="landscape-grid">
      <article class="panel dashboard-card map-card">
        <header><div><span class="kicker">GLOBAL DISTRIBUTION</span><h3>{{ t('dashboard.threatMap') }}</h3></div><span class="map-window">{{ t('dashboard.last24Hours') }}</span></header>
        <svg data-testid="threat-map" class="threat-map" viewBox="0 0 200 120" role="img" :aria-label="t('dashboard.threatMap')">
          <defs><radialGradient id="map-glow"><stop offset="0" stop-color="var(--blue)" stop-opacity=".7" /><stop offset="1" stop-color="var(--blue)" stop-opacity="0" /></radialGradient></defs>
          <g class="map-grid"><path v-for="x in [20,40,60,80,100,120,140,160,180]" :key="`x${x}`" :d="`M ${x} 10 V 110`" /><path v-for="y in [20,40,60,80,100]" :key="`y${y}`" :d="`M 10 ${y} H 190`" /></g>
          <g class="continents">
            <path d="M18 30 31 20 54 22 68 33 60 45 48 47 41 60 31 55 27 43 17 39Z" />
            <path d="M52 65 68 69 76 82 70 103 62 110 57 92 48 76Z" />
            <path d="M84 35 96 27 110 32 120 28 144 31 176 40 183 52 169 62 151 58 142 70 125 66 116 53 103 52 95 60 84 51Z" />
            <path d="M101 61 118 64 127 81 119 103 106 105 98 88 94 71Z" />
            <path d="M151 84 166 78 183 87 177 101 160 105 148 96Z" />
          </g>
          <g v-for="marker in markers" :key="marker.name" data-map-marker class="map-marker">
            <circle :cx="marker.point[0]" :cy="marker.point[1]" :r="marker.radius * 2" fill="url(#map-glow)" />
            <circle :cx="marker.point[0]" :cy="marker.point[1]" :r="marker.radius" />
            <title>{{ marker.name }}: {{ marker.count }}</title>
          </g>
        </svg>
        <div class="map-caption"><span><i></i>{{ t('dashboard.activeThreatSignal') }}</span><b>{{ n(dashboard.summary.malicious_last_24h) }}</b></div>
      </article>

      <article class="panel dashboard-card landscape-trend">
        <header><div><span class="kicker">INTELLIGENCE VELOCITY</span><h3>{{ t('dashboard.sevenDayThreats') }}</h3></div></header>
        <DashboardSparkline :values="dashboard.sections.trend.items.map((item) => item.malicious)" :labels="dashboard.sections.trend.items.map((item) => item.date)" />
      </article>

      <article v-for="(section, key) in { countries: dashboard.sections.countries, regions: dashboard.sections.regions, labels: dashboard.sections.labels, severities: dashboard.sections.severities }" :key="key" class="panel dashboard-card rank-card">
        <header><div><span class="kicker">TOP 10</span><h3>{{ t(`dashboard.rankings.${key}`) }}</h3></div></header>
        <div v-if="section.items.length" class="rank-list">
          <div v-for="(item, index) in section.items" :key="item.name"><span>{{ String(index + 1).padStart(2, '0') }}</span><div><b>{{ item.name }}</b><i><em :style="{ width: width(item, section.items) }"></em></i></div><strong>{{ n(item.count) }}</strong></div>
        </div>
        <p v-else class="dashboard-empty">{{ t('dashboard.emptyRankings') }}</p>
      </article>
    </section>
  </div>
</template>
