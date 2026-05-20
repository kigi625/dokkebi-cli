// backend/controllers/order.controller.ts
// 주문 처리 컨트롤러

import { router, db } from 'dokkebi:runtime';
import { orders, orderItems, products } from '../models/index.js';
import { eq } from 'dokkebi-dsl';

interface CartItem {
  productId: string;
  productName: string;
  price: number;
  quantity: number;
}

// POST /api/orders — 주문 생성
router.post('/api/orders', async (ctx) => {
  const { customerName, customerEmail, items } = ctx.body || {};
  if (!customerName || !customerEmail) return ctx.badRequest('customerName, customerEmail은 필수입니다.');
  if (!items || !Array.isArray(items) || items.length === 0) return ctx.badRequest('items는 하나 이상이 필요합니다.');

  const totalPrice = (items as CartItem[]).reduce((s, i) => s + i.price * i.quantity, 0);

  const { rows: orderRows } = await db
    .insert(orders, { customerName, customerEmail, totalPrice, status: 'pending' })
    .returning()
    .exec();

  const order = orderRows[0];

  for (const item of items as CartItem[]) {
    await db.insert(orderItems, {
      orderId: order.id, productId: item.productId,
      productName: item.productName, price: item.price, quantity: item.quantity,
    }).exec();

    const { rows: pRows } = await db
      .select(products, ['id', 'stock'])
      .where(eq(products.id, item.productId))
      .limit(1)
      .exec();

    if (pRows.length > 0) {
      const newStock = Math.max(0, Number(pRows[0].stock) - item.quantity);
      await db.update(products, { stock: newStock }).where(eq(products.id, item.productId)).exec();
    }
  }

  return ctx.json({ order: { ...order, items } }, 201);
});

// GET /api/orders — 주문 목록
router.get('/api/orders', async (ctx) => {
  const { rows } = await db
    .select(orders)
    .orderBy(orders.createdAt, 'desc')
    .limit(Number(ctx.query?.limit || 20))
    .exec();
  return ctx.json({ orders: rows });
});

// GET /api/orders/:id — 주문 상세 (아이템 포함)
router.get('/api/orders/:id', async (ctx) => {
  const { rows: orderRows } = await db
    .select(orders)
    .where(eq(orders.id, ctx.params.id))
    .limit(1)
    .exec();
  if (!orderRows.length) return ctx.notFound('주문을 찾을 수 없습니다.');

  const { rows: itemRows } = await db
    .select(orderItems)
    .where(eq(orderItems.orderId, ctx.params.id))
    .exec();

  return ctx.json({ order: { ...orderRows[0], items: itemRows } });
});

// PATCH /api/orders/:id/status — 주문 상태 변경
router.patch('/api/orders/:id/status', async (ctx) => {
  const { status } = ctx.body || {};
  const valid = ['pending', 'paid', 'shipped', 'cancelled'];
  if (!valid.includes(status)) return ctx.badRequest(`status는 ${valid.join(' | ')} 중 하나여야 합니다.`);
  await db.update(orders, { status }).where(eq(orders.id, ctx.params.id)).exec();
  return ctx.json({ success: true });
});
