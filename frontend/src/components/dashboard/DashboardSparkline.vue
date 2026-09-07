<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  values: number[]
  labels?: string[]
}>()

const points = computed(() => {
  const values = props.values.length ? props.values : [0]
  const maximum = Math.max(...values, 1)
  const denominator = Math.max(values.length - 1, 1)
  return values.map((value, index) => {
    const x = 6 + (index / denominator) * 188
    const y = 66 - (value / maximum) * 54
    return `${x.toFixed(1)},${y.toFixed(1)}`
  }).join(' ')
})

const areaPoints = computed(() => `6,70 ${points.value} 194,70`)
</script>

<template>
  <div class="sparkline-wrap">
    <svg class="sparkline" viewBox="0 0 200 76" role="img">
      <defs>
        <linearGradient id="spark-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stop-color="var(--blue)" stop-opacity=".35" />
          <stop offset="1" stop-color="var(--blue)" stop-opacity="0" />
        </linearGradient>
      </defs>
      <line v-for="line in [18, 35, 52, 69]" :key="line" x1="4" :y1="line" x2="196" :y2="line" class="spark-grid" />
      <polygon :points="areaPoints" fill="url(#spark-fill)" />
      <polyline :points="points" class="spark-path" />
    </svg>
    <div v-if="labels?.length" class="spark-labels">
      <span v-for="label in labels" :key="label">{{ label.slice(5) }}</span>
    </div>
  </div>
</template>
