import vue from '@vitejs/plugin-vue';

export default {
  plugins: [vue()],
  root: '.',
  build: {
    outDir: 'dist',
  },
};
