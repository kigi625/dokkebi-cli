<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { dokkebi } from './lib/dokkebi';

interface Product {
  id: string; name: string; description: string; price: number;
  stock: number; category: string; imageUrl: string;
}
interface CartItem extends Product { quantity: number; }
interface Order {
  id: string; customerName: string; customerEmail: string;
  totalPrice: number; status: string; createdAt: string;
}
interface User { id: string; name: string; email: string; role: string; }

// ── 런타임 상태 ───────────────────────────────────────────
const ready   = ref(false);
const initErr = ref('');

// ── 인증 상태 ─────────────────────────────────────────────
const currentUser = ref<User | null>(null);
const authToken   = ref(localStorage.getItem('dokkebi_token') || '');
const authView    = ref<'login' | 'register'>('login');
const authForm    = ref({ name: '', email: '', password: '' });
const authErr     = ref('');
const authLoading = ref(false);

// ── 쇼핑 상태 ─────────────────────────────────────────────
const tab      = ref<'shop' | 'orders' | 'admin'>('shop');
const products = ref<Product[]>([]);
const orders   = ref<Order[]>([]);
const cart     = ref<CartItem[]>([]);
const catFilter = ref('전체');

const showCart  = ref(false);
const showOrder = ref(false);
const showAdd   = ref(false);
const loading   = ref(false);
const toast     = ref('');

const orderForm = ref({ customerName: '', customerEmail: '' });
const newProd   = ref({ name: '', description: '', price: '', stock: '', category: '일반', imageUrl: '' });

const categories = ['전체', '일반', '의류', '굿즈', '액세서리'];
const filtered  = computed(() =>
  catFilter.value === '전체' ? products.value : products.value.filter(p => p.category === catFilter.value)
);
const cartCount = computed(() => cart.value.reduce((s, i) => s + i.quantity, 0));
const cartTotal = computed(() => cart.value.reduce((s, i) => s + i.price * i.quantity, 0));

// ── 초기화 ────────────────────────────────────────────────
async function waitForDokkebi(ms = 8000) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    try { await dokkebi.ready(); return; }
    catch { /* 부트스트랩 미준비 — 잠시 대기 후 재시도 */ }
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('dokkebi 런타임 초기화 시간 초과');
}

async function api(method: string, path: string, body?: unknown, token?: string) {
  const headers: Record<string, string> = {};
  if (token || authToken.value) headers['Authorization'] = `Bearer ${token ?? authToken.value}`;
  const res = await dokkebi.request({ method, path, body, headers });
  if (!res.ok) throw new Error(res.error || `HTTP ${res.status}`);
  return res.json;
}
function tabFromHash(): 'shop' | 'orders' | 'admin' {
  const h = (location.hash || '').replace(/^#/, '').replace(/^\//, '');
  if (h === 'orders' || h === 'admin' || h === 'shop') return h;
  return 'shop';
}
function setHashTab(t: 'shop' | 'orders' | 'admin') {
  const target = '#/' + t;
  if (location.hash !== target) location.hash = target;
}

onMounted(async () => {
  try {
    await waitForDokkebi();
    ready.value = true;
    tab.value = tabFromHash();
    if (!location.hash) setHashTab(tab.value);
    const onHash = () => {
      const next = tabFromHash();
      tab.value = next;
      if (next === 'orders') loadOrders();
      if (next === 'admin') loadProducts();
    };
    window.addEventListener('hashchange', onHash);
    if (authToken.value) {
      try {
        const { user } = await api('GET', '/api/auth/me');
        currentUser.value = user;
        orderForm.value.customerName  = user.name;
        orderForm.value.customerEmail = user.email;
      } catch { authToken.value = ''; localStorage.removeItem('dokkebi_token'); }
    }
    await loadProducts();
    if (tab.value === 'orders') await loadOrders();
  } catch (e: any) { initErr.value = e.message; }
});

// ── 인증 ─────────────────────────────────────────────────
async function doAuth() {
  authErr.value = ''; authLoading.value = true;
  try {
    const path = authView.value === 'login' ? '/api/auth/login' : '/api/auth/register';
    const body: any = authView.value === 'login'
      ? { email: authForm.value.email, password: authForm.value.password }
      : { name: authForm.value.name, email: authForm.value.email, password: authForm.value.password };
    const data = await api('POST', path, body, '');
    authToken.value = data.token;
    localStorage.setItem('dokkebi_token', data.token);
    currentUser.value = data.user;
    orderForm.value.customerName  = data.user.name;
    orderForm.value.customerEmail = data.user.email;
    showToast(`✅ ${authView.value === 'login' ? '로그인' : '회원가입'} 완료! 안녕하세요, ${data.user.name}님`);
  } catch (e: any) { authErr.value = e.message; }
  finally { authLoading.value = false; }
}
function doLogout() {
  authToken.value = ''; currentUser.value = null;
  localStorage.removeItem('dokkebi_token');
  cart.value = []; showToast('로그아웃됐습니다.');
}

// ── 데이터 로드 ───────────────────────────────────────────
async function loadProducts() {
  loading.value = true;
  try { products.value = (await api('GET', '/api/products')).products || []; }
  finally { loading.value = false; }
}
async function loadOrders() {
  loading.value = true;
  try { orders.value = (await api('GET', '/api/orders')).orders || []; }
  finally { loading.value = false; }
}
async function switchTab(t: 'shop' | 'orders' | 'admin') {
  tab.value = t;
  setHashTab(t);
  if (t === 'orders') loadOrders();
  if (t === 'admin') loadProducts();
}

// ── 상품 관리 ─────────────────────────────────────────────
async function addProduct() {
  if (!newProd.value.name || !newProd.value.price) { showToast('상품명과 가격을 입력해주세요.'); return; }
  loading.value = true;
  try {
    await api('POST', '/api/products', {
      name: newProd.value.name, description: newProd.value.description,
      price: Number(newProd.value.price), stock: Number(newProd.value.stock || 0),
      category: newProd.value.category, imageUrl: newProd.value.imageUrl,
    });
    showToast('상품 등록 완료!');
    newProd.value = { name: '', description: '', price: '', stock: '', category: '일반', imageUrl: '' };
    showAdd.value = false; await loadProducts();
  } catch (e: any) { showToast('오류: ' + e.message); }
  finally { loading.value = false; }
}
async function deleteProd(id: string) {
  if (!confirm('삭제하시겠습니까?')) return;
  await api('DELETE', `/api/products/${id}`); await loadProducts(); showToast('삭제됨');
}

// ── 장바구니 ─────────────────────────────────────────────
function addToCart(p: Product) {
  const ex = cart.value.find(i => i.id === p.id);
  if (ex) { if (ex.quantity >= p.stock) { showToast('재고 부족'); return; } ex.quantity++; }
  else { if (!p.stock) { showToast('품절'); return; } cart.value.push({ ...p, quantity: 1 }); }
  showToast(`🛒 ${p.name} 담김`);
}
function removeFromCart(id: string) { cart.value = cart.value.filter(i => i.id !== id); }
function changeQty(id: string, d: number) {
  const i = cart.value.find(i => i.id === id);
  if (i) i.quantity = Math.max(1, i.quantity + d);
}
async function placeOrder() {
  if (!orderForm.value.customerName || !orderForm.value.customerEmail) { showToast('이름과 이메일을 입력해주세요.'); return; }
  loading.value = true;
  try {
    await api('POST', '/api/orders', {
      customerName: orderForm.value.customerName, customerEmail: orderForm.value.customerEmail,
      items: cart.value.map(i => ({ productId: i.id, productName: i.name, price: i.price, quantity: i.quantity })),
    });
    showToast('✅ 주문 완료!'); cart.value = [];
    showOrder.value = false; showCart.value = false; await loadProducts(); await loadOrders();
  } catch (e: any) { showToast('오류: ' + e.message); }
  finally { loading.value = false; }
}

function showToast(msg: string) { toast.value = msg; setTimeout(() => toast.value = '', 2800); }
function fmt(n: number | null | undefined) { return (Number(n) || 0).toLocaleString('ko-KR') + '원'; }
function statusLabel(s: string) { return ({ pending: '결제대기', paid: '결제완료', shipped: '배송중', cancelled: '취소' }[s] ?? s); }
</script>

<template>
  <!-- 초기화 중 -->
  <div v-if="!ready" style="position:fixed;inset:0;display:flex;align-items:center;justify-content:center;flex-direction:column;gap:16px;background:#fff">
    <div v-if="!initErr" style="text-align:center">
      <div style="font-size:3rem">🏮</div>
      <p style="color:#666;margin:0">도깨비 런타임 초기화 중...</p>
    </div>
    <div v-else style="color:#e74c3c;text-align:center;padding:20px">
      <div style="font-size:2rem">⚠️</div>
      <p>초기화 실패: {{ initErr }}</p>
    </div>
  </div>

  <div v-else style="min-height:100vh;background:#f5f5f5;font-family:system-ui">

    <!-- ── 헤더 ─────────────────────────────────── -->
    <header style="background:#fff;box-shadow:0 2px 8px rgba(0,0,0,.08);position:sticky;top:0;z-index:10;padding:0 24px;height:60px;display:flex;align-items:center;justify-content:space-between;gap:16px">
      <div style="display:flex;align-items:center;gap:8px;flex-shrink:0">
        <span style="font-size:1.8rem">🏮</span>
        <div>
          <p style="font-weight:900;color:#6c5ce7;margin:0;font-size:1.1rem">Dokkebi Shop</p>
          <p style="font-size:.7rem;color:#aaa;margin:0">WASM Serverless</p>
        </div>
      </div>
      <nav style="display:flex;gap:6px;flex-wrap:wrap">
        <button v-for="[key,label] in [['shop','🛍 쇼핑'],['orders','📦 주문내역'],['admin','⚙ 관리']]"
          :key="key" @click="switchTab(key as any)"
          :style="{padding:'6px 14px',borderRadius:'20px',border:'none',cursor:'pointer',fontWeight:600,background:tab===key?'#6c5ce7':'#eee',color:tab===key?'#fff':'#333',fontSize:'.85rem'}">
          {{ label }}
        </button>
      </nav>
      <div style="display:flex;align-items:center;gap:10px;flex-shrink:0">
        <!-- 미로그인: 로그인/회원가입 버튼 -->
        <template v-if="!currentUser">
          <button @click="authView='login'"
            style="padding:6px 14px;background:none;border:1.5px solid #6c5ce7;border-radius:20px;color:#6c5ce7;cursor:pointer;font-weight:600;font-size:.85rem">
            로그인
          </button>
          <button @click="authView='register'"
            style="padding:6px 14px;background:#6c5ce7;border:none;border-radius:20px;color:#fff;cursor:pointer;font-weight:600;font-size:.85rem">
            회원가입
          </button>
        </template>
        <!-- 로그인 상태: 사용자 + 로그아웃 -->
        <template v-else>
          <span style="font-size:.85rem;color:#555">👤 {{ currentUser.name }}</span>
          <button @click="doLogout"
            style="padding:5px 12px;background:#ffe0e0;border:none;border-radius:20px;color:#c0392b;cursor:pointer;font-weight:600;font-size:.8rem">
            로그아웃
          </button>
        </template>
        <!-- 장바구니 -->
        <button @click="showCart = true"
          style="position:relative;background:#6c5ce7;color:#fff;border:none;border-radius:50%;width:40px;height:40px;font-size:1.1rem;cursor:pointer;flex-shrink:0">
          🛒
          <span v-if="cartCount > 0"
            style="position:absolute;top:-4px;right:-4px;background:#e84393;color:#fff;border-radius:50%;width:18px;height:18px;font-size:.65rem;display:flex;align-items:center;justify-content:center;font-weight:700">
            {{ cartCount }}
          </span>
        </button>
      </div>
    </header>

    <!-- ── 인증 패널 (로그인/회원가입) ─────────────── -->
    <div v-if="!currentUser" style="max-width:420px;margin:60px auto;padding:0 20px">
      <div style="background:#fff;border-radius:20px;box-shadow:0 4px 24px rgba(0,0,0,.1);overflow:hidden">
        <!-- 탭 전환 -->
        <div style="display:flex;border-bottom:1px solid #eee">
          <button @click="authView='login'; authErr=''"
            :style="{flex:1,padding:'16px',border:'none',cursor:'pointer',fontWeight:700,fontSize:'1rem',background:authView==='login'?'#6c5ce7':'#fff',color:authView==='login'?'#fff':'#999'}">
            로그인
          </button>
          <button @click="authView='register'; authErr=''"
            :style="{flex:1,padding:'16px',border:'none',cursor:'pointer',fontWeight:700,fontSize:'1rem',background:authView==='register'?'#6c5ce7':'#fff',color:authView==='register'?'#fff':'#999'}">
            회원가입
          </button>
        </div>
        <div style="padding:28px">
          <div style="text-align:center;margin-bottom:24px">
            <span style="font-size:2.5rem">🏮</span>
            <p style="font-weight:700;margin:8px 0 0;color:#333">{{ authView === 'login' ? '다시 만나서 반가워요!' : '도깨비 가입을 환영합니다!' }}</p>
          </div>
          <!-- 이름 (회원가입만) -->
          <label v-if="authView==='register'" style="display:block;margin-bottom:14px">
            <span style="font-weight:600;font-size:.85rem;color:#555;display:block;margin-bottom:5px">이름</span>
            <input v-model="authForm.name" placeholder="홍길동" autocomplete="name"
              style="width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:10px;font-size:1rem;box-sizing:border-box;outline:none"
              @focus="($event.target as HTMLInputElement).style.borderColor='#6c5ce7'"
              @blur="($event.target as HTMLInputElement).style.borderColor='#ddd'" />
          </label>
          <!-- 이메일 -->
          <label style="display:block;margin-bottom:14px">
            <span style="font-weight:600;font-size:.85rem;color:#555;display:block;margin-bottom:5px">이메일</span>
            <input v-model="authForm.email" type="email" placeholder="example@email.com" autocomplete="email"
              style="width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:10px;font-size:1rem;box-sizing:border-box;outline:none"
              @focus="($event.target as HTMLInputElement).style.borderColor='#6c5ce7'"
              @blur="($event.target as HTMLInputElement).style.borderColor='#ddd'" />
          </label>
          <!-- 비밀번호 -->
          <label style="display:block;margin-bottom:20px">
            <span style="font-weight:600;font-size:.85rem;color:#555;display:block;margin-bottom:5px">비밀번호</span>
            <input v-model="authForm.password" type="password" placeholder="8자 이상" autocomplete="current-password"
              style="width:100%;padding:11px 14px;border:1.5px solid #ddd;border-radius:10px;font-size:1rem;box-sizing:border-box;outline:none"
              @focus="($event.target as HTMLInputElement).style.borderColor='#6c5ce7'"
              @blur="($event.target as HTMLInputElement).style.borderColor='#ddd'"
              @keyup.enter="doAuth" />
          </label>
          <!-- 에러 -->
          <div v-if="authErr" style="background:#fff0f0;border:1px solid #ffb3b3;border-radius:8px;padding:10px 14px;margin-bottom:16px;color:#c0392b;font-size:.88rem">
            {{ authErr }}
          </div>
          <!-- 제출 -->
          <button @click="doAuth" :disabled="authLoading"
            style="width:100%;padding:13px;background:#6c5ce7;color:#fff;border:none;border-radius:12px;font-weight:700;cursor:pointer;font-size:1rem">
            {{ authLoading ? '처리 중...' : (authView === 'login' ? '로그인' : '가입하기') }}
          </button>
          <p style="text-align:center;margin-top:16px;font-size:.85rem;color:#999">
            {{ authView === 'login' ? '계정이 없으신가요?' : '이미 계정이 있으신가요?' }}
            <a @click.prevent="authView = authView==='login'?'register':'login'; authErr=''"
              href="#" style="color:#6c5ce7;font-weight:600;margin-left:4px">
              {{ authView === 'login' ? '회원가입' : '로그인' }}
            </a>
          </p>
        </div>
      </div>
      <!-- 로그인 없이 쇼핑 둘러보기 -->
      <p style="text-align:center;margin-top:20px;font-size:.85rem;color:#aaa">
        <a @click.prevent="currentUser = { id:'guest', name:'게스트', email:'', role:'user' }"
          href="#" style="color:#aaa">로그인 없이 둘러보기 →</a>
      </p>
    </div>

    <!-- ── 쇼핑 탭 ────────────────────────────────── -->
    <main v-if="currentUser && tab === 'shop'" style="max-width:1200px;margin:0 auto;padding:32px 24px">
      <div style="display:flex;gap:8px;margin-bottom:24px;flex-wrap:wrap">
        <button v-for="cat in categories" :key="cat" @click="catFilter = cat"
          :style="{padding:'6px 16px',borderRadius:'20px',border:'2px solid #6c5ce7',cursor:'pointer',fontWeight:600,background:catFilter===cat?'#6c5ce7':'#fff',color:catFilter===cat?'#fff':'#6c5ce7'}">
          {{ cat }}
        </button>
      </div>
      <div v-if="loading" style="text-align:center;padding:60px;color:#aaa">로딩 중...</div>
      <div v-else-if="!filtered.length" style="text-align:center;padding:60px;color:#aaa">상품이 없습니다.</div>
      <div v-else style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:20px">
        <div v-for="p in filtered" :key="p.id"
          style="background:#fff;border-radius:16px;overflow:hidden;box-shadow:0 2px 12px rgba(0,0,0,.06);transition:transform .15s"
          @mouseenter="($event.currentTarget as HTMLElement).style.transform='translateY(-4px)'"
          @mouseleave="($event.currentTarget as HTMLElement).style.transform=''">
          <img :src="p.imageUrl || `https://placehold.co/400x300/6c5ce7/white?text=${encodeURIComponent(p.name)}`"
            :alt="p.name" style="width:100%;height:180px;object-fit:cover" />
          <div style="padding:16px">
            <span style="font-size:.7rem;background:#f0edff;color:#6c5ce7;padding:2px 8px;border-radius:20px">{{ p.category }}</span>
            <p style="font-weight:700;margin:8px 0 4px">{{ p.name }}</p>
            <p style="font-size:.82rem;color:#888;margin-bottom:12px;height:36px;overflow:hidden">{{ p.description }}</p>
            <div style="display:flex;justify-content:space-between;align-items:center">
              <span style="font-weight:900;color:#6c5ce7;font-size:1.05rem">{{ fmt(p.price) }}</span>
              <button @click="addToCart(p)" :disabled="!p.stock"
                :style="{padding:'6px 14px',background:p.stock?'#6c5ce7':'#ccc',color:'#fff',border:'none',borderRadius:'8px',cursor:p.stock?'pointer':'not-allowed',fontWeight:600}">
                {{ p.stock ? '담기' : '품절' }}
              </button>
            </div>
          </div>
        </div>
      </div>
    </main>

    <!-- ── 주문내역 탭 ─────────────────────────────── -->
    <main v-if="currentUser && tab === 'orders'" style="max-width:800px;margin:0 auto;padding:32px 24px">
      <h2 style="margin:0 0 24px">📦 주문 내역</h2>
      <div v-if="loading" style="text-align:center;color:#aaa;padding:60px 0">로딩 중...</div>
      <div v-else-if="!orders.length" style="text-align:center;color:#aaa;padding:60px 0">주문 내역이 없습니다.</div>
      <div v-for="o in orders" :key="o.id"
        style="background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 2px 8px rgba(0,0,0,.06)">
        <div style="display:flex;justify-content:space-between">
          <div>
            <p style="font-weight:700;margin:0">{{ o.customerName }}</p>
            <p style="color:#888;font-size:.85rem;margin:4px 0">{{ o.customerEmail }}</p>
          </div>
          <div style="text-align:right">
            <span :style="{padding:'3px 10px',borderRadius:'20px',fontSize:'.8rem',fontWeight:700,background:{pending:'#fff3cd',paid:'#d4edda',shipped:'#d1ecf1',cancelled:'#f8d7da'}[o.status]||'#eee'}">
              {{ statusLabel(o.status) }}
            </span>
            <p style="font-weight:900;color:#6c5ce7;margin:4px 0">{{ fmt(o.totalPrice) }}</p>
            <p style="font-size:.75rem;color:#aaa">{{ o.createdAt?.slice(0, 16) }}</p>
          </div>
        </div>
      </div>
    </main>

    <!-- ── 관리 탭 ─────────────────────────────────── -->
    <main v-if="currentUser && tab === 'admin'" style="max-width:900px;margin:0 auto;padding:32px 24px">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:24px">
        <h2 style="margin:0">⚙ 상품 관리</h2>
        <button @click="showAdd = true"
          style="background:#6c5ce7;color:#fff;border:none;border-radius:8px;padding:8px 18px;cursor:pointer;font-weight:700">
          + 상품 추가
        </button>
      </div>
      <table style="width:100%;background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.06);border-collapse:collapse">
        <thead><tr style="border-bottom:2px solid #eee">
          <th style="padding:12px 16px;text-align:left">상품명</th>
          <th style="padding:12px 16px;text-align:left">카테고리</th>
          <th style="padding:12px 16px;text-align:right">가격</th>
          <th style="padding:12px 16px;text-align:right">재고</th>
          <th style="padding:12px 16px"></th>
        </tr></thead>
        <tbody>
          <tr v-for="p in products" :key="p.id" style="border-bottom:1px solid #f5f5f5">
            <td style="padding:12px 16px;font-weight:600">{{ p.name }}</td>
            <td style="padding:12px 16px;color:#888;font-size:.85rem">{{ p.category }}</td>
            <td style="padding:12px 16px;text-align:right;color:#6c5ce7;font-weight:700">{{ fmt(p.price) }}</td>
            <td style="padding:12px 16px;text-align:right" :style="{color:p.stock===0?'#e84393':p.stock<10?'#f39c12':'#27ae60'}">{{ p.stock }}개</td>
            <td style="padding:12px 16px">
              <button @click="deleteProd(p.id)" style="background:#ffe0e0;color:#c0392b;border:none;border-radius:6px;padding:4px 10px;cursor:pointer;font-weight:600">삭제</button>
            </td>
          </tr>
        </tbody>
      </table>
    </main>

    <!-- ── 장바구니 사이드바 ───────────────────────── -->
    <div v-if="showCart" style="position:fixed;inset:0;z-index:50;display:flex">
      <div style="flex:1;background:rgba(0,0,0,.4)" @click="showCart = false"></div>
      <div style="width:360px;background:#fff;display:flex;flex-direction:column;height:100%">
        <div style="padding:20px;border-bottom:1px solid #eee;display:flex;justify-content:space-between;align-items:center">
          <h3 style="margin:0">🛒 장바구니</h3>
          <button @click="showCart = false" style="background:none;border:none;font-size:1.4rem;cursor:pointer">✕</button>
        </div>
        <div style="flex:1;overflow-y:auto;padding:20px">
          <div v-if="!cart.length" style="text-align:center;color:#aaa;padding:40px 0">비어있습니다</div>
          <div v-for="item in cart" :key="item.id" style="display:flex;gap:12px;margin-bottom:16px;background:#f8f8f8;border-radius:12px;padding:12px">
            <img :src="item.imageUrl || 'https://placehold.co/60x60/6c5ce7/white?text=IMG'" style="width:56px;height:56px;border-radius:8px;object-fit:cover;flex-shrink:0" />
            <div style="flex:1;min-width:0">
              <p style="margin:0;font-weight:600;font-size:.9rem;white-space:nowrap;overflow:hidden;text-overflow:ellipsis">{{ item.name }}</p>
              <p style="margin:4px 0;color:#6c5ce7;font-weight:700;font-size:.9rem">{{ fmt(item.price) }}</p>
              <div style="display:flex;align-items:center;gap:8px">
                <button @click="changeQty(item.id,-1)" style="background:#eee;border:none;border-radius:50%;width:24px;height:24px;cursor:pointer">−</button>
                <span style="font-weight:700;min-width:20px;text-align:center">{{ item.quantity }}</span>
                <button @click="changeQty(item.id,1)"  style="background:#eee;border:none;border-radius:50%;width:24px;height:24px;cursor:pointer">+</button>
              </div>
            </div>
            <button @click="removeFromCart(item.id)" style="background:none;border:none;color:#e74c3c;cursor:pointer;align-self:flex-start">✕</button>
          </div>
        </div>
        <div style="padding:20px;border-top:1px solid #eee">
          <div style="display:flex;justify-content:space-between;margin-bottom:16px">
            <span style="font-weight:600">합계</span>
            <span style="font-weight:900;color:#6c5ce7;font-size:1.1rem">{{ fmt(cartTotal) }}</span>
          </div>
          <button @click="currentUser ? (showOrder = true) : showToast('주문하려면 로그인이 필요합니다.')" :disabled="!cart.length"
            style="width:100%;padding:12px;background:#6c5ce7;color:#fff;border:none;border-radius:10px;font-weight:700;cursor:pointer;font-size:1rem">
            주문하기
          </button>
        </div>
      </div>
    </div>

    <!-- ── 주문 폼 모달 ───────────────────────────── -->
    <div v-if="showOrder" style="position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.5)">
      <div style="background:#fff;border-radius:20px;padding:28px;width:100%;max-width:420px;max-height:90vh;overflow-y:auto">
        <h3 style="margin:0 0 20px">📋 주문 정보</h3>
        <label style="display:block;margin-bottom:12px">
          <span style="font-weight:600;display:block;margin-bottom:4px">이름</span>
          <input v-model="orderForm.customerName" placeholder="홍길동"
            style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:1rem;box-sizing:border-box" />
        </label>
        <label style="display:block;margin-bottom:20px">
          <span style="font-weight:600;display:block;margin-bottom:4px">이메일</span>
          <input v-model="orderForm.customerEmail" type="email" placeholder="example@email.com"
            style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;font-size:1rem;box-sizing:border-box" />
        </label>
        <div style="background:#f8f8f8;border-radius:10px;padding:16px;margin-bottom:20px">
          <div v-for="i in cart" :key="i.id" style="display:flex;justify-content:space-between;font-size:.9rem;margin-bottom:6px">
            <span>{{ i.name }} × {{ i.quantity }}</span>
            <span style="font-weight:600">{{ fmt(i.price * i.quantity) }}</span>
          </div>
          <div style="border-top:1px solid #eee;margin-top:8px;padding-top:8px;display:flex;justify-content:space-between;font-weight:700">
            <span>총 결제금액</span>
            <span style="color:#6c5ce7">{{ fmt(cartTotal) }}</span>
          </div>
        </div>
        <div style="display:flex;gap:12px">
          <button @click="showOrder = false" style="flex:1;padding:12px;background:#eee;border:none;border-radius:10px;cursor:pointer;font-weight:600">취소</button>
          <button @click="placeOrder" :disabled="loading"
            style="flex:1;padding:12px;background:#6c5ce7;color:#fff;border:none;border-radius:10px;cursor:pointer;font-weight:700">
            {{ loading ? '처리 중...' : '결제하기' }}
          </button>
        </div>
      </div>
    </div>

    <!-- ── 상품 추가 모달 ─────────────────────────── -->
    <div v-if="showAdd" style="position:fixed;inset:0;z-index:60;display:flex;align-items:center;justify-content:center;padding:20px;background:rgba(0,0,0,.5)">
      <div style="background:#fff;border-radius:20px;padding:28px;width:100%;max-width:440px;max-height:90vh;overflow-y:auto">
        <h3 style="margin:0 0 20px">+ 상품 추가</h3>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">
          <label style="grid-column:1/-1">
            <span style="font-weight:600;display:block;margin-bottom:4px">상품명 *</span>
            <input v-model="newProd.name" placeholder="상품명" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box" />
          </label>
          <label>
            <span style="font-weight:600;display:block;margin-bottom:4px">가격 *</span>
            <input v-model="newProd.price" type="number" placeholder="0" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box" />
          </label>
          <label>
            <span style="font-weight:600;display:block;margin-bottom:4px">재고</span>
            <input v-model="newProd.stock" type="number" placeholder="0" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box" />
          </label>
          <label>
            <span style="font-weight:600;display:block;margin-bottom:4px">카테고리</span>
            <select v-model="newProd.category" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box">
              <option v-for="c in ['일반','의류','굿즈','액세서리']" :key="c">{{ c }}</option>
            </select>
          </label>
          <label>
            <span style="font-weight:600;display:block;margin-bottom:4px">이미지 URL</span>
            <input v-model="newProd.imageUrl" placeholder="https://..." style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;box-sizing:border-box" />
          </label>
          <label style="grid-column:1/-1">
            <span style="font-weight:600;display:block;margin-bottom:4px">설명</span>
            <textarea v-model="newProd.description" rows="2" placeholder="상품 설명" style="width:100%;padding:10px;border:1px solid #ddd;border-radius:8px;resize:none;font-family:inherit;box-sizing:border-box"></textarea>
          </label>
        </div>
        <div style="display:flex;gap:12px;margin-top:20px">
          <button @click="showAdd = false" style="flex:1;padding:12px;background:#eee;border:none;border-radius:10px;cursor:pointer;font-weight:600">취소</button>
          <button @click="addProduct" :disabled="loading"
            style="flex:1;padding:12px;background:#6c5ce7;color:#fff;border:none;border-radius:10px;cursor:pointer;font-weight:700">
            등록
          </button>
        </div>
      </div>
    </div>

    <!-- ── 토스트 ──────────────────────────────────── -->
    <div v-if="toast" style="position:fixed;bottom:24px;left:50%;transform:translateX(-50%);background:#333;color:#fff;padding:10px 24px;border-radius:24px;font-weight:600;font-size:.9rem;z-index:100;white-space:nowrap">
      {{ toast }}
    </div>
    </div>
</template>
