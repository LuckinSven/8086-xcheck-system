export default {
  common: {
    appName: 'XCheck',
    dashboard: '首页',
    newQuery: '新建查询',
    queryHistory: '查询历史',
    threatbookHistory: '微步历史',
    systemSettings: '系统设置',
    save: '保存',
    cancel: '取消',
    loading: '加载中…',
    retry: '重试',
  },
  settings: {
    appearanceAndLanguage: '外观与语言',
    language: '语言',
    theme: '界面皮肤',
    homepage: '首页模式',
    motion: '动效强度',
  },
  errors: {
    request: {
      validation_failed: '请求中的 {field} 值无效。',
      failed: '请求失败。',
    },
    task: {
      not_found: '任务不存在。',
      upload_too_large: '上传文件超过 {limit_mb} MB 限制。',
      retry_invalid_state: '只有失败或部分成功的任务可以重试。',
      step_not_found: '任务节点不存在。',
      claim_conflict: '任务已被其他请求领取。',
      threatbook_not_ready: '任务尚未进入微步查询阶段。',
      threatbook_config_invalid: '已保存的微步执行配置无效。',
      whitelist_action_invalid: '当前任务无法执行白名单移除。',
      original_not_available: '手动输入任务没有原始文件。',
      original_file_missing: '原始文件已不可用。',
      ip_not_found: 'IP 记录不存在。',
    },
    integration: {
      whitelist: {
        invalid_response: '白名单接口返回结构不正确。',
        test_failed: '白名单接口连接测试失败。',
      },
      threatbook: {
        api_key_required: '尚未配置微步 API Key。',
        test_failed: '微步接口认证测试失败。',
      },
    },
  },
} as const
