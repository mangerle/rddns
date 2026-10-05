<script setup lang="ts">
import { useConfigStore } from '@/stores/config'
import TaskDetail from './TaskDetail.vue'
import TaskList from './TaskList.vue'

const configStore = useConfigStore()
</script>

<template>
  <div class="flex-1 flex overflow-hidden">
    <TaskList />
    <TaskDetail
      v-if="configStore.currentTask"
      :task="configStore.currentTask"
    />
    <div
      v-else
      class="flex-1 flex items-center justify-center text-slate-500 text-sm"
    >
      请选择或新建一个解析任务
    </div>
  </div>
</template>
