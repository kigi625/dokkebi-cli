import { useEffect, useState } from 'react';
import { useDokkebi } from '../composables/useDokkebi';

export default function Dashboard() {
  const { get } = useDokkebi();
  const [user, setUser] = useState<any>(null);

  useEffect(() => {
    const token = localStorage.getItem('dokkebi_token');
    if (!token) { window.location.hash = '#/login'; return; }
    get('/api/auth/me').then((data) => setUser(data.user));
  }, []);

  return (
    <div>
      <h1>대시보드</h1>
      {user && <p>안녕하세요, {user.name}님!</p>}
    </div>
  );
}
