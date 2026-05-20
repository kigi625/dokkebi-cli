<template>
  <div style="padding: 2rem; font-family: sans-serif;">
    <h1>Dokkebi Example</h1>
    <p>Backend status: <span :style="{ color: status ? 'green' : 'gray' }">{{ status || 'waiting...' }}</span></p>
    <button @click="fetchHello" :disabled="!backendReady">Call /api/hello</button>
    <pre v-if="message">{{ message }}</pre>
  </div>
</template>

<script setup>
import { ref, onMounted } from 'vue';

const status = ref('');
const message = ref('');
const backendReady = ref(false);

onMounted(async () => {
  if (window.dokkebiReady) {
    await window.dokkebiReady();
    backendReady.value = true;
    status.value = 'ready';
    const r = await fetch('/api/health');
    const j = await r.json();
    status.value = j.ok ? 'ok' : 'error';
  } else {
    status.value = 'no dokkebi';
  }
});

async function fetchHello() {
  const r = await fetch('/api/hello');
  const j = await r.json();
  message.value = JSON.stringify(j, null, 2);
}
</script>
