<template>
  <form @submit.prevent="handleLogin">
    <h1>로그인</h1>
    <input v-model="email" placeholder="이메일" type="email" />
    <input v-model="password" placeholder="비밀번호" type="password" />
    <button type="submit">로그인</button>
  </form>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { useDokkebi } from '../composables/useDokkebi';

const { post } = useDokkebi();
const email = ref('');
const password = ref('');

async function handleLogin() {
  const data = await post<any>('/api/auth/login', { email: email.value, password: password.value });
  localStorage.setItem('dokkebi_token', data.token);
  window.location.hash = '#/dashboard';
}
</script>
