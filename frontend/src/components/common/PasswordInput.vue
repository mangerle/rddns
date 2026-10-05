<script setup lang="ts">
import { Eye, EyeOff } from 'lucide-vue-next'
import { ref } from 'vue'
import { useI18n } from 'vue-i18n'

defineProps<{
  modelValue?: string | null
  placeholder?: string
  disabled?: boolean
}>()

const emit = defineEmits<{
  (e: 'update:modelValue', val: string): void
}>()

const { t } = useI18n()
const isVisible = ref(false)

function toggle() {
  isVisible.value = !isVisible.value
}
</script>

<template>
  <div class="relative flex items-center w-full">
    <input
      :type="isVisible ? 'text' : 'password'"
      :value="modelValue || ''"
      :placeholder="placeholder"
      :disabled="disabled"
      class="w-full bg-slate-50 dark:bg-slate-950/60 border border-slate-300 dark:border-slate-700/80 rounded-lg px-3.5 py-2 pr-10 text-sm text-slate-800 dark:text-slate-100 placeholder-slate-400 dark:placeholder-slate-500 focus:border-indigo-500 focus:ring-1 focus:ring-indigo-500 transition-all disabled:opacity-50"
      @input="emit('update:modelValue', ($event.target as HTMLInputElement).value)"
    >
    <button
      type="button"
      tabindex="-1"
      :title="isVisible ? t('auth.hidePassword') : t('auth.showPassword')"
      class="absolute right-2.5 p-1 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition focus:outline-none cursor-pointer"
      @click="toggle"
    >
      <EyeOff v-if="isVisible" class="w-4 h-4" />
      <Eye v-else class="w-4 h-4" />
    </button>
  </div>
</template>
