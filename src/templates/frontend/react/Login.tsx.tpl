import { useState } from 'react';
import { useDokkebi } from '../composables/useDokkebi';

export default function Login() {
  const { post } = useDokkebi();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  async function handleLogin(e: React.FormEvent) {
    e.preventDefault();
    const data = await post<any>('/api/auth/login', { email, password });
    localStorage.setItem('dokkebi_token', data.token);
    window.location.hash = '#/dashboard';
  }

  return (
    <form onSubmit={handleLogin}>
      <h1>로그인</h1>
      <input value={email} onChange={(e) => setEmail(e.target.value)} placeholder="이메일" type="email" />
      <input value={password} onChange={(e) => setPassword(e.target.value)} placeholder="비밀번호" type="password" />
      <button type="submit">로그인</button>
    </form>
  );
}
