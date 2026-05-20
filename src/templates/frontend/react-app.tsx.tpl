import { useEffect, useState, useMemo } from 'react';
import { dokkebi } from './lib/dokkebi';

interface Product {
  id: string; name: string; description: string; price: number;
  stock: number; category: string; imageUrl: string;
}
interface CartItem extends Product { quantity: number; }
interface Order { id: string; customerName: string; customerEmail: string; totalPrice: number; status: string; createdAt: string; }

async function waitForDokkebi(ms = 8000) {
  const t = Date.now();
  while (Date.now() - t < ms) {
    try { await dokkebi.ready(); return; }
    catch { /* 부트스트랩 미준비 — 잠시 대기 후 재시도 */ }
    await new Promise(r => setTimeout(r, 50));
  }
  throw new Error('dokkebi 런타임 초기화 시간 초과');
}
async function api(method: string, path: string, body?: unknown) {
  const res = await dokkebi.request({ method, path, body });
  if (!res.ok) throw new Error(res.error || 'HTTP ' + res.status);
  return res.json;
}
function fmt(n: number | null | undefined) { return (Number(n) || 0).toLocaleString('ko-KR') + '원'; }
type Tab = 'shop' | 'orders' | 'admin';
function _tabFromHash(): Tab {
  const h = (window.location.hash || '').replace(/^#/, '').replace(/^\//, '');
  if (h === 'orders' || h === 'admin' || h === 'shop') return h;
  return 'shop';
}
function _setHashTab(tab: Tab) {
  const target = '#/' + tab;
  if (window.location.hash !== target) window.location.hash = target;
}

export default function App() {
  const [ready, setReady] = useState(false);
  const [initErr, setInitErr] = useState('');
  const [tab, setTab] = useState<Tab>(() => _tabFromHash());
  const [products, setProducts] = useState<Product[]>([]);
  const [orders, setOrders] = useState<Order[]>([]);
  const [cart, setCart] = useState<CartItem[]>([]);
  const [catFilter, setCatFilter] = useState('전체');
  const [showCart, setShowCart] = useState(false);
  const [showOrder, setShowOrder] = useState(false);
  const [showAdd, setShowAdd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [toast, setToast] = useState('');
  const [orderForm, setOrderForm] = useState({ customerName:'', customerEmail:'' });
  const [newProd, setNewProd] = useState({ name:'', description:'', price:'', stock:'', category:'일반', imageUrl:'' });

  const filtered = useMemo(() => catFilter === '전체' ? products : products.filter(p => p.category === catFilter), [products, catFilter]);
  const cartCount = useMemo(() => cart.reduce((s, i) => s + i.quantity, 0), [cart]);
  const cartTotal = useMemo(() => cart.reduce((s, i) => s + i.price * i.quantity, 0), [cart]);

  function showToast(msg: string) { setToast(msg); setTimeout(() => setToast(''), 2500); }

  useEffect(() => {
    waitForDokkebi().then(() => {
      setReady(true);
      loadProducts();
      if (_tabFromHash() === 'orders') loadOrders();
    }).catch(e => setInitErr(e.message));
  }, []);
  useEffect(() => {
    const onHash = () => {
      const next = _tabFromHash();
      setTab(next);
      if (next === 'orders') loadOrders();
    };
    window.addEventListener('hashchange', onHash);
    if (!window.location.hash) _setHashTab(_tabFromHash());
    return () => window.removeEventListener('hashchange', onHash);
  }, []);

  async function loadProducts() {
    setLoading(true);
    try { setProducts((await api('GET', '/api/products')).products || []); }
    finally { setLoading(false); }
  }
  async function loadOrders() {
    setLoading(true);
    try { setOrders((await api('GET', '/api/orders')).orders || []); }
    finally { setLoading(false); }
  }
  function switchTab(t: Tab) { setTab(t); _setHashTab(t); if (t === 'orders') loadOrders(); }

  function addToCart(p: Product) {
    setCart(prev => {
      const ex = prev.find(i => i.id === p.id);
      if (ex) { if (ex.quantity >= p.stock) { showToast('재고 부족'); return prev; } return prev.map(i => i.id === p.id ? {...i, quantity: i.quantity+1} : i); }
      if (!p.stock) { showToast('품절'); return prev; }
      return [...prev, {...p, quantity: 1}];
    });
    showToast(`🛒 ${p.name} 담김`);
  }
  function removeFromCart(id: string) { setCart(prev => prev.filter(i => i.id !== id)); }
  function changeQty(id: string, d: number) { setCart(prev => prev.map(i => i.id === id ? {...i, quantity: Math.max(1, i.quantity+d)} : i)); }

  async function placeOrder() {
    if (!orderForm.customerName || !orderForm.customerEmail) { showToast('이름과 이메일을 입력해주세요.'); return; }
    setLoading(true);
    try {
      await api('POST', '/api/orders', { customerName: orderForm.customerName, customerEmail: orderForm.customerEmail,
        items: cart.map(i => ({ productId: i.id, productName: i.name, price: i.price, quantity: i.quantity })) });
      showToast('✅ 주문 완료!'); setCart([]); setOrderForm({ customerName:'', customerEmail:'' });
      setShowOrder(false); setShowCart(false); loadProducts(); loadOrders();
    } catch(e: any) { showToast('오류: ' + e.message); }
    finally { setLoading(false); }
  }

  async function addProduct() {
    if (!newProd.name || !newProd.price) { showToast('상품명과 가격을 입력해주세요.'); return; }
    setLoading(true);
    try {
      await api('POST', '/api/products', { name: newProd.name, description: newProd.description,
        price: Number(newProd.price), stock: Number(newProd.stock||0), category: newProd.category, imageUrl: newProd.imageUrl });
      showToast('상품 등록 완료!');
      setNewProd({ name:'', description:'', price:'', stock:'', category:'일반', imageUrl:'' });
      setShowAdd(false); loadProducts();
    } catch(e: any) { showToast('오류: ' + e.message); }
    finally { setLoading(false); }
  }

  async function deleteProd(id: string) {
    if (!confirm('삭제하시겠습니까?')) return;
    await api('DELETE', `/api/products/${id}`); loadProducts(); showToast('삭제됨');
  }

  if (!ready) return (
    <div style={{ position:'fixed', inset:0, display:'flex', alignItems:'center', justifyContent:'center', flexDirection:'column', gap:16 }}>
      {initErr ? <p style={{ color:'red' }}>초기화 실패: {initErr}</p> : <><div style={{ fontSize:'3rem' }}>🏮</div><p>도깨비 초기화 중...</p></>}
    </div>
  );

  const btnStyle = (active: boolean) => ({ padding:'6px 14px', borderRadius:20, border:'none', cursor:'pointer' as const, fontWeight:600, background: active ? '#6c5ce7' : '#eee', color: active ? '#fff' : '#333' });

  return (
    <div style={{ minHeight:'100vh', background:'#f5f5f5', fontFamily:'system-ui' }}>
      {/* 헤더 */}
      <header style={{ background:'#fff', boxShadow:'0 2px 8px rgba(0,0,0,.08)', position:'sticky', top:0, zIndex:10, padding:'0 24px', height:60, display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:'1.8rem' }}>🏮</span>
          <div><p style={{ fontWeight:900, color:'#6c5ce7', margin:0 }}>Dokkebi Shop</p><p style={{ fontSize:'.7rem', color:'#999', margin:0 }}>WASM Serverless</p></div>
        </div>
        <nav style={{ display:'flex', gap:8 }}>
          {(['shop','orders','admin'] as const).map(t => <button key={t} style={btnStyle(tab===t)} onClick={() => switchTab(t)}>{({shop:'🛍 쇼핑',orders:'📦 주문내역',admin:'⚙ 관리'}[t])}</button>)}
        </nav>
        <button onClick={() => setShowCart(true)} style={{ position:'relative', background:'#6c5ce7', color:'#fff', border:'none', borderRadius:'50%', width:42, height:42, cursor:'pointer', fontSize:'1.2rem' }}>
          🛒
          {cartCount > 0 && <span style={{ position:'absolute', top:-4, right:-4, background:'#e84393', color:'#fff', borderRadius:'50%', width:18, height:18, fontSize:'.65rem', display:'flex', alignItems:'center', justifyContent:'center', fontWeight:700 }}>{cartCount}</span>}
        </button>
      </header>

      {/* 쇼핑 탭 */}
      {tab === 'shop' && <main style={{ maxWidth:1200, margin:'0 auto', padding:'32px 24px' }}>
        <div style={{ display:'flex', gap:8, marginBottom:24, flexWrap:'wrap' }}>
          {['전체','일반','의류','굿즈','액세서리'].map(c => <button key={c} onClick={() => setCatFilter(c)} style={{ ...btnStyle(catFilter===c), border:'2px solid #6c5ce7', background: catFilter===c ? '#6c5ce7' : '#fff', color: catFilter===c ? '#fff' : '#6c5ce7' }}>{c}</button>)}
        </div>
        {loading ? <p style={{ textAlign:'center', color:'#999' }}>로딩 중...</p> :
          <div style={{ display:'grid', gridTemplateColumns:'repeat(auto-fill,minmax(220px,1fr))', gap:20 }}>
            {filtered.map(p => (
              <div key={p.id} style={{ background:'#fff', borderRadius:16, overflow:'hidden', boxShadow:'0 2px 12px rgba(0,0,0,.06)' }}>
                <img src={p.imageUrl || `https://placehold.co/400x300/6c5ce7/white?text=${encodeURIComponent(p.name)}`} alt={p.name} style={{ width:'100%', height:180, objectFit:'cover' }} />
                <div style={{ padding:16 }}>
                  <span style={{ fontSize:'.7rem', background:'#f0edff', color:'#6c5ce7', padding:'2px 8px', borderRadius:20 }}>{p.category}</span>
                  <p style={{ fontWeight:700, margin:'8px 0 4px' }}>{p.name}</p>
                  <p style={{ fontSize:'.82rem', color:'#666', height:36, overflow:'hidden', margin:'0 0 12px' }}>{p.description}</p>
                  <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center' }}>
                    <span style={{ fontWeight:900, color:'#6c5ce7' }}>{fmt(p.price)}</span>
                    <button onClick={() => addToCart(p)} disabled={!p.stock} style={{ padding:'6px 14px', background: p.stock ? '#6c5ce7' : '#ccc', color:'#fff', border:'none', borderRadius:8, cursor: p.stock ? 'pointer' : 'not-allowed', fontWeight:600 }}>{p.stock ? '담기' : '품절'}</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        }
      </main>}

      {/* 주문내역 탭 */}
      {tab === 'orders' && <main style={{ maxWidth:800, margin:'0 auto', padding:'32px 24px' }}>
        <h2>📦 주문 내역</h2>
        {orders.length === 0 ? <p style={{ textAlign:'center', color:'#999' }}>주문 내역이 없습니다.</p> :
          orders.map(o => <div key={o.id} style={{ background:'#fff', borderRadius:12, padding:20, marginBottom:16, boxShadow:'0 2px 8px rgba(0,0,0,.06)', display:'flex', justifyContent:'space-between' }}>
            <div><p style={{ fontWeight:700, margin:0 }}>{o.customerName}</p><p style={{ color:'#666', fontSize:'.85rem', margin:'4px 0' }}>{o.customerEmail}</p></div>
            <div style={{ textAlign:'right' }}>
              <p style={{ fontWeight:900, color:'#6c5ce7', margin:0 }}>{fmt(o.totalPrice)}</p>
              <p style={{ fontSize:'.75rem', color:'#999', margin:'4px 0' }}>{o.createdAt?.slice(0,16)}</p>
            </div>
          </div>)
        }
      </main>}

      {/* 관리 탭 */}
      {tab === 'admin' && <main style={{ maxWidth:900, margin:'0 auto', padding:'32px 24px' }}>
        <div style={{ display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:24 }}>
          <h2 style={{ margin:0 }}>⚙ 상품 관리</h2>
          <button onClick={() => setShowAdd(true)} style={{ background:'#6c5ce7', color:'#fff', border:'none', borderRadius:8, padding:'8px 18px', cursor:'pointer', fontWeight:700 }}>+ 상품 추가</button>
        </div>
        <table style={{ width:'100%', background:'#fff', borderRadius:12, boxShadow:'0 2px 8px rgba(0,0,0,.06)', borderCollapse:'collapse' }}>
          <thead><tr style={{ borderBottom:'2px solid #eee' }}>
            {['상품명','카테고리','가격','재고',''].map(h => <th key={h} style={{ padding:'12px 16px', textAlign:'left' }}>{h}</th>)}
          </tr></thead>
          <tbody>
            {products.map(p => <tr key={p.id} style={{ borderBottom:'1px solid #f5f5f5' }}>
              <td style={{ padding:'12px 16px', fontWeight:600 }}>{p.name}</td>
              <td style={{ padding:'12px 16px', color:'#666', fontSize:'.85rem' }}>{p.category}</td>
              <td style={{ padding:'12px 16px', color:'#6c5ce7', fontWeight:700 }}>{fmt(p.price)}</td>
              <td style={{ padding:'12px 16px', color: p.stock===0?'#e84393':p.stock<10?'#f39c12':'#27ae60' }}>{p.stock}개</td>
              <td style={{ padding:'12px 16px' }}><button onClick={() => deleteProd(p.id)} style={{ background:'#ffe0e0', color:'#c0392b', border:'none', borderRadius:6, padding:'4px 10px', cursor:'pointer', fontWeight:600 }}>삭제</button></td>
            </tr>)}
          </tbody>
        </table>
      </main>}

      {/* 장바구니 사이드바 */}
      {showCart && <div style={{ position:'fixed', inset:0, zIndex:50, display:'flex' }}>
        <div style={{ flex:1, background:'rgba(0,0,0,.4)' }} onClick={() => setShowCart(false)} />
        <div style={{ width:360, background:'#fff', display:'flex', flexDirection:'column', height:'100%' }}>
          <div style={{ padding:20, borderBottom:'1px solid #eee', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
            <h3 style={{ margin:0 }}>🛒 장바구니</h3>
            <button onClick={() => setShowCart(false)} style={{ background:'none', border:'none', fontSize:'1.4rem', cursor:'pointer' }}>✕</button>
          </div>
          <div style={{ flex:1, overflowY:'auto', padding:20 }}>
            {cart.length === 0 ? <p style={{ textAlign:'center', color:'#999', paddingTop:40 }}>비어있습니다</p> :
              cart.map(i => <div key={i.id} style={{ display:'flex', gap:12, marginBottom:16, background:'#f8f8f8', borderRadius:12, padding:12 }}>
                <img src={i.imageUrl || 'https://placehold.co/60x60/6c5ce7/white?text=IMG'} style={{ width:56, height:56, borderRadius:8, objectFit:'cover', flexShrink:0 }} />
                <div style={{ flex:1 }}>
                  <p style={{ margin:0, fontWeight:600, fontSize:'.9rem' }}>{i.name}</p>
                  <p style={{ margin:'4px 0', color:'#6c5ce7', fontWeight:700, fontSize:'.9rem' }}>{fmt(i.price)}</p>
                  <div style={{ display:'flex', alignItems:'center', gap:8 }}>
                    <button onClick={() => changeQty(i.id,-1)} style={{ background:'#eee', border:'none', borderRadius:'50%', width:24, height:24, cursor:'pointer' }}>−</button>
                    <span style={{ fontWeight:700 }}>{i.quantity}</span>
                    <button onClick={() => changeQty(i.id,1)} style={{ background:'#eee', border:'none', borderRadius:'50%', width:24, height:24, cursor:'pointer' }}>+</button>
                  </div>
                </div>
                <button onClick={() => removeFromCart(i.id)} style={{ background:'none', border:'none', color:'#e74c3c', cursor:'pointer', alignSelf:'flex-start' }}>✕</button>
              </div>)
            }
          </div>
          <div style={{ padding:20, borderTop:'1px solid #eee' }}>
            <div style={{ display:'flex', justifyContent:'space-between', marginBottom:16 }}>
              <span style={{ fontWeight:600 }}>합계</span>
              <span style={{ fontWeight:900, color:'#6c5ce7', fontSize:'1.1rem' }}>{fmt(cartTotal)}</span>
            </div>
            <button onClick={() => setShowOrder(true)} disabled={!cart.length}
              style={{ width:'100%', padding:12, background:'#6c5ce7', color:'#fff', border:'none', borderRadius:10, fontWeight:700, cursor:'pointer', fontSize:'1rem' }}>
              주문하기
            </button>
          </div>
        </div>
      </div>}

      {/* 주문 폼 */}
      {showOrder && <div style={{ position:'fixed', inset:0, zIndex:60, display:'flex', alignItems:'center', justifyContent:'center', padding:20, background:'rgba(0,0,0,.5)' }}>
        <div style={{ background:'#fff', borderRadius:20, padding:28, width:'100%', maxWidth:420 }}>
          <h3 style={{ margin:'0 0 20px' }}>📋 주문 정보</h3>
          <input placeholder="이름" value={orderForm.customerName} onChange={e => setOrderForm(f=>({...f, customerName:e.target.value}))} style={{ width:'100%', padding:10, border:'1px solid #ddd', borderRadius:8, marginBottom:12, boxSizing:'border-box' as const, fontSize:'1rem' }} />
          <input placeholder="이메일" type="email" value={orderForm.customerEmail} onChange={e => setOrderForm(f=>({...f, customerEmail:e.target.value}))} style={{ width:'100%', padding:10, border:'1px solid #ddd', borderRadius:8, marginBottom:20, boxSizing:'border-box' as const, fontSize:'1rem' }} />
          <div style={{ display:'flex', gap:12 }}>
            <button onClick={() => setShowOrder(false)} style={{ flex:1, padding:12, background:'#eee', border:'none', borderRadius:10, cursor:'pointer', fontWeight:600 }}>취소</button>
            <button onClick={placeOrder} disabled={loading} style={{ flex:1, padding:12, background:'#6c5ce7', color:'#fff', border:'none', borderRadius:10, cursor:'pointer', fontWeight:700 }}>결제하기</button>
          </div>
        </div>
      </div>}

      {/* 상품 추가 모달 */}
      {showAdd && <div style={{ position:'fixed', inset:0, zIndex:60, display:'flex', alignItems:'center', justifyContent:'center', padding:20, background:'rgba(0,0,0,.5)' }}>
        <div style={{ background:'#fff', borderRadius:20, padding:28, width:'100%', maxWidth:440, maxHeight:'90vh', overflowY:'auto' }}>
          <h3 style={{ margin:'0 0 20px' }}>+ 상품 추가</h3>
          {[['상품명 *','name','text','상품명'],['가격 *','price','number','0'],['재고','stock','number','0'],['이미지 URL','imageUrl','text','https://...']].map(([label, key, type, ph]) =>
            <div key={key} style={{ marginBottom:12 }}>
              <label style={{ fontWeight:600, display:'block', marginBottom:4 }}>{label}</label>
              <input type={type} placeholder={ph} value={(newProd as any)[key]} onChange={e => setNewProd(p => ({...p, [key]: e.target.value}))} style={{ width:'100%', padding:10, border:'1px solid #ddd', borderRadius:8, boxSizing:'border-box' as const }} />
            </div>
          )}
          <div style={{ marginBottom:12 }}>
            <label style={{ fontWeight:600, display:'block', marginBottom:4 }}>설명</label>
            <textarea rows={2} value={newProd.description} onChange={e => setNewProd(p=>({...p,description:e.target.value}))} style={{ width:'100%', padding:10, border:'1px solid #ddd', borderRadius:8, resize:'none', boxSizing:'border-box' as const }} />
          </div>
          <div style={{ display:'flex', gap:12, marginTop:8 }}>
            <button onClick={() => setShowAdd(false)} style={{ flex:1, padding:12, background:'#eee', border:'none', borderRadius:10, cursor:'pointer', fontWeight:600 }}>취소</button>
            <button onClick={addProduct} disabled={loading} style={{ flex:1, padding:12, background:'#6c5ce7', color:'#fff', border:'none', borderRadius:10, cursor:'pointer', fontWeight:700 }}>등록</button>
          </div>
        </div>
      </div>}

      {/* 토스트 */}
      {toast && <div style={{ position:'fixed', bottom:24, left:'50%', transform:'translateX(-50%)', background:'#333', color:'#fff', padding:'10px 24px', borderRadius:24, fontWeight:600, fontSize:'.9rem', zIndex:100 }}>{toast}</div>}
    </div>
  );
}
