export default {
  common: {
    appName: 'XCheck',
    dashboard: 'Dashboard',
    newQuery: 'New Query',
    queryHistory: 'Query History',
    threatbookHistory: 'ThreatBook History',
    systemSettings: 'System Settings',
    save: 'Save',
    cancel: 'Cancel',
    loading: 'Loading…',
    retry: 'Retry',
  },
  settings: {
    appearanceAndLanguage: 'Appearance & Language',
    language: 'Language',
    theme: 'Theme',
    homepage: 'Homepage',
    motion: 'Motion',
  },
  errors: {
    request: {
      validation_failed: 'The request contains an invalid value for {field}.',
      failed: 'The request failed.',
    },
    task: {
      not_found: 'The task does not exist.',
      upload_too_large: 'The uploaded file exceeds the {limit_mb} MB limit.',
      retry_invalid_state: 'Only failed or partially successful tasks can be retried.',
      step_not_found: 'The requested task step does not exist.',
      claim_conflict: 'Another request has already claimed this task.',
      threatbook_not_ready: 'The task has not reached the ThreatBook query stage.',
      threatbook_config_invalid: 'The saved ThreatBook execution settings are invalid.',
      whitelist_action_invalid: 'Whitelist removal is not available for this task.',
      original_not_available: 'Manual-entry tasks do not have an original file.',
      original_file_missing: 'The original file is no longer available.',
      ip_not_found: 'The IP record does not exist.',
    },
    integration: {
      whitelist: {
        invalid_response: 'The whitelist API returned an invalid response.',
        test_failed: 'Whitelist API connection test failed.',
      },
      threatbook: {
        api_key_required: 'The ThreatBook API key has not been configured.',
        test_failed: 'ThreatBook API authentication test failed.',
      },
    },
  },
} as const
