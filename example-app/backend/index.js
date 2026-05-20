const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.get('/api/health', (req, res) => {
  res.json({ ok: true, message: 'dokkebi backend in WebContainer' });
});

app.get('/api/hello', (req, res) => {
  res.json({ message: 'Hello from Express in the browser' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log('Backend listening on port', PORT);
});
