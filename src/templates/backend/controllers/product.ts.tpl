// backend/controllers/product.controller.ts
// 상품 CRUD 컨트롤러

import { router, db } from 'dokkebi:runtime';
import { products } from '../models/index.js';
import { eq } from 'dokkebi-dsl';

// GET /api/products — 상품 목록 (category 필터 가능)
router.get('/api/products', async (ctx) => {
  const category = ctx.query?.category;
  let query = db
    .select(products, ['id', 'name', 'description', 'price', 'stock', 'category', 'imageUrl', 'createdAt'])
    .orderBy(products.createdAt, 'desc')
    .limit(Number(ctx.query?.limit || 50));

  if (category) query = query.where(eq(products.category, category));

  const { rows } = await query.exec();
  return ctx.json({ products: rows });
});

// GET /api/products/:id — 상품 단건 조회
router.get('/api/products/:id', async (ctx) => {
  const { rows } = await db
    .select(products)
    .where(eq(products.id, ctx.params.id))
    .limit(1)
    .exec();

  if (!rows.length) return ctx.notFound('상품을 찾을 수 없습니다.');
  return ctx.json({ product: rows[0] });
});

// POST /api/products — 상품 등록
router.post('/api/products', async (ctx) => {
  const { name, description, price, stock, category, imageUrl } = ctx.body || {};
  if (!name || price === undefined) return ctx.badRequest('name과 price는 필수입니다.');

  const { rows } = await db
    .insert(products, {
      name,
      description: description || '',
      price: Number(price),
      stock: Number(stock || 0),
      category: category || 'general',
      imageUrl: imageUrl || '',
    })
    .returning()
    .exec();

  return ctx.json({ product: rows[0] }, 201);
});

// PUT /api/products/:id — 상품 수정
router.put('/api/products/:id', async (ctx) => {
  const { name, description, price, stock, category, imageUrl } = ctx.body || {};
  const updates: Record<string, unknown> = {};
  if (name !== undefined)        updates.name = name;
  if (description !== undefined) updates.description = description;
  if (price !== undefined)       updates.price = Number(price);
  if (stock !== undefined)       updates.stock = Number(stock);
  if (category !== undefined)    updates.category = category;
  if (imageUrl !== undefined)    updates.imageUrl = imageUrl;

  await db.update(products, updates).where(eq(products.id, ctx.params.id)).exec();
  return ctx.json({ success: true });
});

// DELETE /api/products/:id — 상품 삭제
router.delete('/api/products/:id', async (ctx) => {
  await db.delete(products).where(eq(products.id, ctx.params.id)).exec();
  return ctx.json({ success: true });
});
