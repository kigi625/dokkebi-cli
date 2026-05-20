<template>
  <div>
    <h1>대시보드</h1>
    <p v-if="user">안녕하세요, {{ user.name }}님!</p>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { useDokkebi } from '../composables/useDokkebi';

const { get } = useDokkebi();
const user = ref<any>(null);

onMounted(async () => {
  const token = localStorage.getItem('dokkebi_token');
  if (!token) { window.location.hash = '#/login'; return; }
  const data = await get<any>('/api/auth/me');
  user.value = data.user;
});
</script>
