// backend/models/index.ts
// 🏮 dokkebi 쇼핑몰 — Host-side Model 레이어

import { table, col, t } from 'dokkebi-dsl';

// ── 사용자 테이블 ──────────────────────────────────────────
export const users = table('users', {
  id:           col('id',            t.uuid().primaryKey().default('random')),
  name:         col('name',          t.text().notNull()),
  email:        col('email',         t.text().notNull()),
  passwordHash: col('password_hash', t.text().notNull()),
  role:         col('role',          t.text().default('user')),
  createdAt:    col('created_at',    t.timestamp().default('now')),
});

// ── 상품 테이블 ────────────────────────────────────────────
export const products = table('products', {
  id:          col('id',          t.uuid().primaryKey().default('random')),
  name:        col('name',        t.text().notNull()),
  description: col('description', t.text()),
  price:       col('price',       t.integer().notNull()),
  stock:       col('stock',       t.integer().default(0)),
  category:    col('category',    t.text().default('general')),
  imageUrl:    col('image_url',   t.text()),
  createdAt:   col('created_at',  t.timestamp().default('now')),
});

// ── 주문 테이블 ────────────────────────────────────────────
export const orders = table('orders', {
  id:            col('id',             t.uuid().primaryKey().default('random')),
  customerName:  col('customer_name',  t.text().notNull()),
  customerEmail: col('customer_email', t.text().notNull()),
  totalPrice:    col('total_price',    t.integer().default(0)),
  status:        col('status',         t.enum(['pending','paid','shipped','cancelled']).default('pending')),
  createdAt:     col('created_at',     t.timestamp().default('now')),
});

// ── 주문 상품 테이블 ───────────────────────────────────────
export const orderItems = table('order_items', {
  id:          col('id',           t.uuid().primaryKey().default('random')),
  orderId:     col('order_id',     t.uuid().notNull()),
  productId:   col('product_id',   t.uuid().notNull()),
  productName: col('product_name', t.text().notNull()),
  price:       col('price',        t.integer().notNull()),
  quantity:    col('quantity',     t.integer().default(1)),
});

export type User      = typeof users._columns;
export type Product   = typeof products._columns;
export type Order     = typeof orders._columns;
export type OrderItem = typeof orderItems._columns;
