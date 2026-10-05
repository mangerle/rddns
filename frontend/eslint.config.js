import antfu from '@antfu/eslint-config'

export default antfu({
  type: 'app',
  typescript: true,
  vue: true,
  rules: {
    'no-console': 'off',
    'vue/no-mutating-props': ['error', { shallowOnly: true }],
  },
})
