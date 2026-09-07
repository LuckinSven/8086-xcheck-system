export interface TaskSummary {
  id: string
  status: string
  input_type: string
  original_filename: string | null
  current_step: string
  raw_count: number
  valid_count: number
  invalid_count?: number
  unique_count: number
  whitelist_removed_count: number
  threatbook_ready_count: number
  malicious_count: number
  high_confidence_count: number
  failed_count: number
  error_summary?: string | null
  created_at: string
  threatbook_config?: ThreatbookConfig | null
  steps?: Step[]
}

export interface ThreatbookConfig {
  batch_size: number | null
  safe_ips_per_minute: number | null
  daily_budget: number | null
  max_retries: number | null
}

export interface Step {
  name: string
  status: string
  progress_current: number
  progress_total: number
  current_batch: number
  total_batches: number
  error_summary: string | null
  started_at: string | null
  finished_at: string | null
}

export interface IpItem {
  id: number
  ip: string
  ip_version: number
  is_public: boolean
  stage: string
  occurrence_count: number
  first_position: string | null
  last_position: string | null
}

export interface WhitelistSummary {
  total: number
  hit: number
  clear: number
  error: number
}

export interface WhitelistResult {
  ip: string
  category: string
  result_code: string
  verdict: string
  matches: unknown[]
  request_id: string | null
}

export interface WhitelistResultsPage {
  summary: WhitelistSummary
  items: WhitelistResult[]
  total: number
  page: number
  page_size: number
}

export interface ThreatbookBatch {
  id: string
  batch_number: number
  status: string
  address_count: number
  resolved_count: number
  unresolved_count: number
  attempt_count: number
  response_code: number | null
  response_message: string | null
  created_at: string
  finished_at: string | null
}

export interface ThreatbookResult {
  id: number
  task_ip_id: number
  batch_id: string
  ip: string
  is_malicious: boolean
  confidence_level: string | null
  severity: string | null
  judgments: string[]
  country: string | null
  province: string | null
  city: string | null
  carrier: string | null
  asn_number: number | null
  asn_name: string | null
  scene: string | null
  update_time: string | null
  permalink: string | null
}

export interface ThreatbookHistoryItem {
  task_id: string
  source_name: string
  status: string
  ready_count: number
  completed_count: number
  failed_count: number
  malicious_count: number
  labels: string[]
  label_remaining_count: number
  regions: string[]
  region_remaining_count: number
  created_at: string
  started_at: string | null
  finished_at: string | null
}

export interface ThreatbookFilterOptions {
  labels: string[]
  countries: string[]
  provinces: string[]
  cities: string[]
  severities: string[]
  confidence_levels: string[]
}

export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface TaskDiagnostics {
  task_id: string
  status: string
  current_step: string
  error_summary: string | null
  last_successful_checkpoint: string | null
  attempt_total: number
  batch_total: number
  attempt_limit: number
  batch_limit: number
  attempts: Array<{
    id: number
    step_name: string
    batch_id: string | null
    attempt_number: number
    status: string
    http_status: number | null
    response_code: number | null
    error_type: string | null
    error_message: string | null
    started_at: string
    finished_at: string | null
  }>
  batches: Array<{
    id: string
    batch_number: number
    status: string
    attempt_count: number
    response_code: number | null
    response_message: string | null
    unresolved_count: number
  }>
}

export type UiLanguage = 'en-US' | 'zh-CN'
export type HomepageMode = 'overview' | 'landscape' | 'operations'
export type MotionIntensity = 'off' | 'subtle' | 'medium' | 'strong'

export interface DisplaySettings {
  ui_language: UiLanguage
  theme_id: import('./theme').ThemeId
  homepage_mode: HomepageMode
  motion_intensity: MotionIntensity
}

export interface IntegrationTestSummary {
  status: 'untested' | 'success' | 'failed'
  tested_at: string | null
  latency_ms: number | null
  error_code: string | null
  fallback: string | null
}

export interface SystemSettings extends DisplaySettings {
  whitelist_api_url: string
  threatbook_api_url: string
  threatbook_api_key_configured: boolean
  upload_max_bytes: number
  threatbook_batch_size: number
  threatbook_safe_ips_per_minute: number
  threatbook_daily_budget: number
  threatbook_max_retries: number
  integration_tests: {
    whitelist: IntegrationTestSummary
    threatbook: IntegrationTestSummary
  }
}
