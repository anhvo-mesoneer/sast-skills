---
name: sast-businesslogic
description: >-
  Detect business logic flaws (OWASP A04:2021 Insecure Design) in a codebase
  using a three-phase approach: recon (inventory business-critical operations
  that move money, set prices, change stock or quotas, drive workflows, or
  consume one-time artifacts), batched verify (check each operation for abuse
  paths in parallel subagents, 3 operations each), and merge (consolidate batch
  results). Covers client-trusted prices and totals, numeric abuse, workflow and
  state-machine bypass, race conditions, replay of single-use artifacts and
  webhooks, server-side limit enforcement, and cross-entity consistency.
  Requires sast/architecture.md (run sast-analysis first). Outputs findings to
  sast/businesslogic-results.md. Use when asked to find business logic flaws,
  price manipulation, workflow bypass, race condition, or insecure design bugs.
---

# Business Logic Flaw Detection

You are performing a focused security assessment to find business logic flaws in a codebase. This skill uses a three-phase approach with subagents: **recon** (inventory business-critical operations and the state they touch), **batched verify** (check each operation for abuse paths in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is a Business Logic Flaw

A business logic flaw occurs when the application accepts a request that is syntactically valid and properly authenticated, but that violates a rule the business depends on: what a product costs, how much money an account holds, which step must come before which, how often a voucher may be used, or how many units a plan allows. There is no dangerous sink — every individual call is "safe" — but the values, the order, or the timing the server accepts let an attacker pay less, obtain more, or skip controls. This is OWASP A04:2021 Insecure Design.

The core pattern: *a business invariant (price, quantity, balance, state, limit, or single-use rule) is trusted to the client or is not enforced atomically on the server.*

### What Business Logic Flaws ARE

- Client-trusted values: `{"productId": 42, "quantity": 1, "unitPrice": 0.01}` is charged as sent
- Numeric abuse: `quantity: -5` produces a negative line total that lowers the order total; a transfer of `-100` pulls money from the recipient; `int` overflow turns a huge quantity into a negative price
- Workflow bypass: `POST /api/orders/{id}/ship` succeeds although payment was never captured; an approved request is edited after approval
- Race conditions: 20 parallel `POST /api/vouchers/redeem` requests all pass `if (!voucher.isRedeemed())` before any of them marks it redeemed
- Replay: re-sending a payment-provider webhook or a refund request credits the account twice; an unsigned webhook is accepted as proof of payment
- Limit bypass: a free-trial or per-user quota is enforced only by an Angular route guard or a disabled button
- Cross-entity inconsistency: a coupon from tenant A applied to tenant B's cart; refund amount larger than the captured amount; transfer to self to farm rewards

### What Business Logic Flaws are NOT

Do not flag these as business logic flaws:

- **IDOR / object ownership**: User A reads or modifies user B's order by changing an ID — that's sast-idor
- **Missing authentication or role checks**: An endpoint with no login, or a regular user reaching an admin function — that's sast-missingauth
- **Mass assignment**: The framework auto-binds privileged entity fields (`role`, `isAdmin`, `balance`, `status`) from the request body — that's sast-massassignment. Business logic covers values the endpoint *deliberately* reads from the client and then wrongly trusts (e.g., a `unitPrice` field in a checkout DTO)
- **Login brute force, OTP/MFA rate limiting, password reset token flaws** — that's sast-authn (the business action executed *after* a successful OTP is in scope here)
- **Injection in the same endpoints** (SQL, XSS, template, command) — that's sast-sqli, sast-xss, sast-ssti, sast-rce
- **Forging JWT claims** to change role or plan — that's sast-jwt

### Patterns That Prevent Business Logic Flaws

When you see these patterns, the operation is likely **not vulnerable** for the corresponding check:

**1. Server-side recomputation of prices and totals**
```
# Java / TypeScript — the request carries only productId + quantity; the price comes from the catalog
BigDecimal line = productRepository.findById(item.productId()).orElseThrow().getPrice().multiply(BigDecimal.valueOf(item.quantity()));
const amountCents = (await this.products.findOneByOrFail({ id: dto.productId })).priceCents * dto.quantity;
```

**2. Server-side bounds validation (actually wired in)**
```
# Java — Bean Validation, effective only with @Valid / @Validated on the parameter
public record CheckoutItem(@NotNull Long productId, @Min(1) @Max(100) int quantity) {}
# TypeScript — class-validator, effective only when ValidationPipe is registered
export class TransferDto { @IsInt() @IsPositive() @Max(1_000_000) amountCents: number; }
# Python — DRF serializer
quantity = serializers.IntegerField(min_value=1, max_value=100)
```

**3. Explicit state machine with allowed transitions**
```
if (!order.getStatus().canTransitionTo(OrderStatus.SHIPPED)) throw new IllegalStateException();
UPDATE orders SET status = 'SHIPPED' WHERE id = ? AND status = 'PAID'   -- 0 rows = invalid transition
```

**4. Atomicity: locks, conditional updates, unique constraints**
```
UPDATE accounts SET balance = balance - ? WHERE id = ? AND balance >= ?     -- check affected rows
@Lock(LockModeType.PESSIMISTIC_WRITE) Optional<Account> findByIdForUpdate(Long id);   // Java (FOR UPDATE); or @Version
Account.objects.select_for_update().get(id=id)   /   query.with_for_update()   /   lockForUpdate()   /   with_lock
CREATE UNIQUE INDEX ux_redemption_voucher ON voucher_redemptions (voucher_id);   -- second redemption fails
```

**5. Verified, idempotent external callbacks**
```
Event event = Webhook.constructEvent(payload, sigHeader, endpointSecret);   // Java (Stripe), raw body
const event = stripe.webhooks.constructEvent(rawBody, sig, endpointSecret); // Node (Stripe)
INSERT INTO processed_events (event_id) VALUES (?)                          -- duplicate key = already handled
```

---

## Vulnerable vs. Secure Examples

### Java — Spring Boot (JPA): Checkout Totals and Quantities

```java
// VULNERABLE: unit price from the request; quantity unbounded (negative/zero allowed)
public record CheckoutItem(Long productId, int quantity, BigDecimal unitPrice) {}
@PostMapping("/api/checkout")
public OrderDto checkout(@RequestBody List<CheckoutItem> items, @AuthenticationPrincipal AppUser user) {
    BigDecimal total = items.stream()
        .map(i -> i.unitPrice().multiply(BigDecimal.valueOf(i.quantity())))
        .reduce(BigDecimal.ZERO, BigDecimal::add);
    paymentGateway.charge(user, total);                  // charges whatever the client computed
    return OrderDto.from(orderRepository.save(new Order(user, items, total)));
}

// VULNERABLE: int arithmetic — quantity 2_000_000 * priceCents 1_999 overflows to a negative total
int totalCents = item.getQuantity() * product.getPriceCents();

// SECURE: ids + bounded quantities only; catalog price; coupon validated server-side; fixed scale
public record CheckoutItem(@NotNull Long productId, @Min(1) @Max(100) int quantity) {}
public record CheckoutRequest(@NotEmpty @Size(max = 50) List<@Valid CheckoutItem> items, String couponCode) {}
@PostMapping("/api/checkout")
@Transactional
public OrderDto checkout(@Valid @RequestBody CheckoutRequest req, @AuthenticationPrincipal AppUser user) {
    BigDecimal total = BigDecimal.ZERO;
    for (CheckoutItem i : req.items()) {
        Product p = productRepository.findByIdAndTenantId(i.productId(), user.getTenantId()).orElseThrow();
        total = total.add(p.getPrice().multiply(BigDecimal.valueOf(i.quantity())));
    }
    total = couponService.apply(req.couponCode(), user, total);   // tenant, expiry, floor at zero
    return OrderDto.from(orderRepository.save(new Order(user, req.items(), total.setScale(2, RoundingMode.HALF_EVEN))));
}
```

### Java — Spring Boot (JPA): Balance and Voucher Race Conditions

```java
// VULNERABLE: check-then-act. @Transactional uses the DB default isolation (READ COMMITTED on PostgreSQL):
// two concurrent requests both read balance=100, both pass, both write 20. Also: amount <= 0, fromId == toId.
@Transactional
public void transfer(Long fromId, Long toId, BigDecimal amount) {
    Account from = accountRepository.findById(fromId).orElseThrow();
    if (from.getBalance().compareTo(amount) < 0) throw new InsufficientFundsException();
    from.setBalance(from.getBalance().subtract(amount));
    accountRepository.findById(toId).orElseThrow().credit(amount);
}

// VULNERABLE: single-use flag checked and set separately; credit granted before the flag is set
Voucher v = voucherRepository.findByCode(code).orElseThrow();
if (v.isRedeemed()) throw new AlreadyRedeemedException();
walletService.credit(user, v.getValue());
v.setRedeemed(true);

// SECURE: atomic conditional update; 0 rows = insufficient funds or lost race
// (alternatives: @Lock(LockModeType.PESSIMISTIC_WRITE) on a findByIdForUpdate query = SELECT ... FOR UPDATE,
//  or @Version on the entity -> ObjectOptimisticLockingFailureException for the losing writer)
@Modifying
@Query("UPDATE Account a SET a.balance = a.balance - :amt WHERE a.id = :id AND a.balance >= :amt")
int debitIfSufficient(@Param("id") Long id, @Param("amt") BigDecimal amt);
@Transactional
public void transfer(Long fromId, Long toId, BigDecimal amount) {
    if (amount.signum() <= 0 || amount.scale() > 2 || fromId.equals(toId)) throw new IllegalArgumentException();
    if (accountRepository.debitIfSufficient(fromId, amount) == 0) throw new InsufficientFundsException();
    accountRepository.credit(toId, amount);
}

// SECURE: claim the voucher atomically; only the request that sets redeemedAt gets the credit
@Modifying
@Query("UPDATE Voucher v SET v.redeemedBy = :uid, v.redeemedAt = CURRENT_TIMESTAMP " +
       "WHERE v.code = :code AND v.redeemedAt IS NULL AND v.expiresAt > CURRENT_TIMESTAMP")
int claim(@Param("code") String code, @Param("uid") Long uid);
```

### Java — Spring Boot: Order Workflow and Payment Webhook

```java
// VULNERABLE: any target status accepted — CREATED -> SHIPPED skips payment, REFUNDED -> PAID reopens
@PatchMapping("/api/orders/{id}/status")
@Transactional
public void updateStatus(@PathVariable Long id, @RequestBody StatusRequest req) {
    orderService.getOwnedOrder(id).setStatus(req.status());   // ownership is fine; transition is not
}

// VULNERABLE: provider callback trusted blindly — no signature, no dedup, amount from payload
@PostMapping("/webhooks/payment")
@Transactional
public void onPayment(@RequestBody PaymentEvent event) {
    Order o = orderRepository.findById(event.orderId()).orElseThrow();
    o.setStatus(OrderStatus.PAID);
    walletService.credit(o.getCustomer(), event.amount());   // replay = double credit
}

// SECURE: explicit allowed-transition table, checked before any side effect
public enum OrderStatus {
    CREATED, PAID, SHIPPED, DELIVERED, CANCELLED, REFUNDED;
    private static final Map<OrderStatus, Set<OrderStatus>> ALLOWED = Map.of(
        CREATED, Set.of(PAID, CANCELLED), PAID, Set.of(SHIPPED, REFUNDED),
        SHIPPED, Set.of(DELIVERED), DELIVERED, Set.of(REFUNDED));
    public boolean canTransitionTo(OrderStatus next) { return ALLOWED.getOrDefault(this, Set.of()).contains(next); }
}

// SECURE: verify signature on raw body, dedupe by event ID, reconcile with the stored order
@PostMapping("/webhooks/stripe")
@Transactional
public ResponseEntity<Void> onStripe(@RequestBody String payload, @RequestHeader("Stripe-Signature") String sig)
        throws SignatureVerificationException {
    Event event = Webhook.constructEvent(payload, sig, endpointSecret);        // throws if forged
    if (processedEventRepository.insertIfAbsent(event.getId()) == 0) return ResponseEntity.ok().build();
    PaymentIntent pi = (PaymentIntent) event.getDataObjectDeserializer().getObject().orElseThrow();
    Order o = orderRepository.findByPaymentIntentIdForUpdate(pi.getId()).orElseThrow();
    if (o.getStatus() != OrderStatus.CREATED || !Objects.equals(pi.getAmountReceived(), o.getTotalCents())
            || !pi.getCurrency().equalsIgnoreCase(o.getCurrency())) throw new IllegalStateException("Mismatch");
    o.setStatus(OrderStatus.PAID);
    return ResponseEntity.ok().build();
}
```

### TypeScript — NestJS / TypeORM

```typescript
// VULNERABLE: total trusted from the client; no validation decorators (-5, 0.5, 1e309, "3" all pass);
// coupon not scoped to tenant or checked for expiry
export class CreateOrderDto { productId: string; quantity: number; total: number; couponCode?: string; }
@Post('orders')
async create(@Body() dto: CreateOrderDto, @Req() req) {
  const coupon = dto.couponCode ? await this.coupons.findOneBy({ code: dto.couponCode }) : null;
  return this.orders.save({ userId: req.user.id, ...dto, amount: dto.total - (coupon?.discount ?? 0) });
}

// SECURE: bounded DTO (global ValidationPipe({ whitelist: true, transform: true })), server-side price,
// coupon scoped to tenant and checked for expiry, total floored at zero
export class CreateOrderDto {
  @IsUUID() productId: string;
  @IsInt() @Min(1) @Max(100) quantity: number;
  @IsOptional() @IsString() couponCode?: string;
}
@Post('orders')
async create(@Body() dto: CreateOrderDto, @Req() req) {
  const product = await this.products.findOneByOrFail({ id: dto.productId, tenantId: req.user.tenantId });
  let amountCents = product.priceCents * dto.quantity;
  if (dto.couponCode) {
    const coupon = await this.coupons.findOneBy({ code: dto.couponCode, tenantId: req.user.tenantId, active: true });
    if (!coupon || coupon.expiresAt < new Date()) throw new BadRequestException('Invalid coupon');
    amountCents = Math.max(0, amountCents - coupon.discountCents);
  }
  return this.orders.save({ userId: req.user.id, productId: product.id, quantity: dto.quantity,
                            amountCents, currency: product.currency, status: 'CREATED' });
}
// TypeORM atomic debit: update(Account).set({ balance: () => 'balance - :amount' })
//   .where('id = :id AND balance >= :amount') -> reject unless result.affected === 1
```

### TypeScript — Express / Prisma

```typescript
// VULNERABLE: NaN bypass — Number("abc") is NaN and `NaN > balance` is false, so the check passes
const amount = Number(req.body.amount);
if (amount > wallet.balance) return res.status(400).json({ error: 'Insufficient funds' });

// VULNERABLE: check-then-act across awaits — 20 parallel requests all see redeemedAt === null
const v = await prisma.voucher.findUnique({ where: { code: req.body.code } });
if (!v || v.redeemedAt) return res.status(400).end();
await prisma.wallet.update({ where: { userId: req.user.id }, data: { balance: { increment: v.value } } });
await prisma.voucher.update({ where: { id: v.id }, data: { redeemedAt: new Date() } });

// SECURE: strict schema + atomic claim inside a transaction (count !== 1 => already used / expired)
const { code } = z.object({ code: z.string().min(8).max(64) }).parse(req.body);
await prisma.$transaction(async (tx) => {
  const claimed = await tx.voucher.updateMany({
    where: { code, redeemedAt: null, expiresAt: { gt: new Date() } },
    data: { redeemedAt: new Date(), redeemedBy: req.user.id },
  });
  if (claimed.count !== 1) throw new HttpError(409, 'Voucher already used');
  const v = await tx.voucher.findUniqueOrThrow({ where: { code } });
  await tx.wallet.update({ where: { userId: req.user.id }, data: { balance: { increment: v.value } } });
});
```

### TypeScript — Angular (frontend-only enforcement)

```typescript
// VULNERABLE (if the backend does not repeat the check): these only shape the UI —
// the API is still callable directly with curl or a proxy
this.form = this.fb.group({ quantity: [1, [Validators.min(1), Validators.max(10)]] });
// <button [disabled]="!user().isPremium" (click)="export()">Export</button>
// { path: 'premium', component: PremiumComponent, canActivate: [premiumGuard] }
this.http.post('/api/orders', { productId, quantity, total: this.cartTotal() });   // client-computed total

// SECURE: Angular sends identifiers and quantities only; the Spring/NestJS endpoint re-checks plan,
// bounds, and limits, and recomputes the total server-side (see the backend examples above)
this.http.post('/api/orders', { productId, quantity });
```

### Python — Django / Flask

```python
# VULNERABLE (Django): client price, negative quantity, check-then-act on stock (lost update)
product = Product.objects.get(id=request.POST['product_id'])
qty = int(request.POST['quantity'])
if product.stock >= qty:
    product.stock -= qty
    product.save()
    Order.objects.create(user=request.user, product=product, qty=qty, total=Decimal(request.POST['price']) * qty)

# SECURE (Django, inside transaction.atomic): bounds check, atomic conditional decrement, catalog price
qty, pid = int(request.POST['quantity']), request.POST['product_id']
if not 1 <= qty <= 10:
    return HttpResponseBadRequest()
if Product.objects.filter(id=pid, stock__gte=qty).update(stock=F('stock') - qty) != 1:
    return HttpResponseBadRequest('Out of stock')
product = Product.objects.get(id=pid)
Order.objects.create(user=request.user, product=product, qty=qty, total=product.price * qty)

# VULNERABLE (Flask/SQLAlchemy): refund amount from request — no cap, no state check, repeatable
gateway.refund(order.payment_id, Decimal(request.json['amount']))

# SECURE (Flask/SQLAlchemy): row lock, refundable state, cumulative refunds capped at captured amount
order = Order.query.filter_by(id=order_id, user_id=current_user.id).with_for_update().first_or_404()
amount = Decimal(request.json['amount']).quantize(Decimal('0.01'))
if order.status not in ('PAID', 'PARTIALLY_REFUNDED') or not (0 < amount <= order.captured - order.refunded):
    abort(400)
```

### Go

```go
// VULNERABLE: read, compare, write — concurrent requests interleave; amount <= 0 accepted
db.QueryRowContext(ctx, "SELECT balance FROM wallets WHERE user_id = $1", userID).Scan(&bal)
if bal < amount {
    return ErrInsufficient
}
db.ExecContext(ctx, "UPDATE wallets SET balance = $1 WHERE user_id = $2", bal-amount, userID)

// SECURE: bounds check, then atomic conditional update with RowsAffected check
if amount <= 0 || amount > MaxWithdrawalCents {
    return ErrInvalidAmount
}
res, err := db.ExecContext(ctx,
    "UPDATE wallets SET balance = balance - $1 WHERE user_id = $2 AND balance >= $1", amount, userID)
if err != nil {
    return err
}
if n, _ := res.RowsAffected(); n != 1 {
    return ErrInsufficient
}
```

### PHP — Laravel

```php
// VULNERABLE: plan taken from the request with no verified payment; trial can be restarted
$request->user()->update(['plan' => $request->input('plan')]);            // "enterprise" for free
$request->user()->update(['trial_ends_at' => now()->addDays(14)]);        // repeatable

// SECURE: plan derived from a verified, paid checkout session; trial claimed atomically once
$session = $this->stripe->checkout->sessions->retrieve($request->input('session_id'));
abort_unless($session->payment_status === 'paid'
    && $session->client_reference_id === (string) $request->user()->id, 402);
$request->user()->update(['plan' => Plan::fromStripePrice($session->metadata->price_id)]);

$claimed = User::whereKey($request->user()->id)->whereNull('trial_used_at')
    ->update(['trial_used_at' => now(), 'trial_ends_at' => now()->addDays(14)]);
abort_if($claimed === 0, 409, 'Trial already used');
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: seat booking check-then-act; Seats may be negative; no concurrency token
var ev = await _db.Events.FindAsync(id);
if (ev.SeatsLeft < req.Seats) return BadRequest();
ev.SeatsLeft -= req.Seats;
_db.Bookings.Add(new Booking(ev.Id, UserId, req.Seats));
await _db.SaveChangesAsync();

// SECURE: public record BookingRequest([Range(1, 10)] int Seats); atomic conditional update (EF Core 7+)
// in a transaction (alternative: [Timestamp] byte[] RowVersion -> DbUpdateConcurrencyException)
await using var tx = await _db.Database.BeginTransactionAsync();
var updated = await _db.Events.Where(e => e.Id == id && e.SeatsLeft >= req.Seats)
    .ExecuteUpdateAsync(s => s.SetProperty(e => e.SeatsLeft, e => e.SeatsLeft - req.Seats));
if (updated != 1) return Conflict("Sold out");
_db.Bookings.Add(new Booking(id, UserId, req.Seats));
await _db.SaveChangesAsync();
await tx.CommitAsync();
```

### Ruby on Rails

```ruby
# VULNERABLE: self-referral allowed, reward claimable repeatedly
referrer = User.find_by!(referral_code: params[:code])
current_user.update!(referred_by: referrer)
referrer.increment!(:credits, 10)

# SECURE: reject self-referral; one reward per referee enforced by a unique index on referee_id
return head :unprocessable_entity if referrer.id == current_user.id
User.transaction do
  ReferralReward.create!(referrer: referrer, referee: current_user)  # RecordNotUnique on repeat -> 409
  current_user.update!(referred_by: referrer)
  referrer.increment!(:credits, 10)                                  # atomic UPDATE ... + 10
end
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/businesslogic-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-businesslogic` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Inventory Business-Critical Operations

Launch a subagent with the following instructions:

> **Goal**: Build an inventory of every business-critical operation in the codebase — every endpoint, service method, message consumer, or scheduled job that moves money or credit, sets prices or totals, changes inventory or quotas, advances a multi-step workflow, consumes a one-time artifact, or enforces a usage limit. For each, record the entity, the state fields involved, which values come from the client, and the persistence call(s). Write results to `sast/businesslogic-recon.md`.
>
> **Context**: You will be given the project's architecture summary. Use it to understand the business domain (e-commerce, banking, SaaS billing, booking, onboarding), the tech stack, all entry points (REST controllers, GraphQL resolvers, message consumers, scheduled jobs), and the persistence layer.
>
> **What to search for — business-critical operations**:
>
> There is no single dangerous sink for this class. Identify operations by their domain meaning: start from the domain entities in the architecture summary, then search route definitions, service classes, DTOs/request records, entities, and migrations for the vocabulary below. Flag every matching operation — you are not yet deciding whether it is abusable; that is Phase 2's job.
>
> 1. **Money and credit movement**: payments, charges, captures, refunds, transfers, withdrawals, payouts, top-ups, wallet/balance/credit adjustments
>    - Names: `pay`, `charge`, `capture`, `refund`, `transfer`, `withdraw`, `payout`, `topUp`, `deposit`, `credit`, `debit`, `balance`, `wallet`, `ledger`
>    - Java: `@PostMapping("/payments")`, `account.setBalance(...)`, `BigDecimal.add/subtract` on balance fields; TypeScript: `@Post('refund')`, `router.post('/transfer', ...)`, `prisma.wallet.update(...)`
>    - Payment provider SDKs and their callback/webhook/IPN handlers: Stripe, Adyen, PayPal, Braintree, Datatrans, Saferpay, TWINT
>
> 2. **Pricing, totals, and discounts**: cart/checkout/order creation, quote calculation, fee/tax/shipping computation, coupons, promo codes, gift cards, loyalty points, referral bonuses
>    - Request fields: `price`, `unitPrice`, `amount`, `total`, `subtotal`, `discount`, `fee`, `tax`, `shipping`, `currency`, `exchangeRate`, `couponCode`, `promoCode`, `giftCard`, `points`
>    - Java: request records/DTOs with `BigDecimal price` or `int quantity` bound via `@RequestBody`; TypeScript: `class CreateOrderDto { total: number }`, `req.body.amount`
>
> 3. **Inventory, quotas, and capacity**: stock decrement, reservations, seat/ticket/slot booking, credit or API-call consumption, storage or member limits
>    - Names: `stock`, `inventory`, `quantity`, `reserve`, `allocate`, `seats`, `capacity`, `quota`, `remaining`, `usage`, `decrement`
>
> 4. **Multi-step workflows and state machines**: order lifecycle, approval chains (submit → approve → execute), KYC/onboarding, checkout wizards, subscription upgrade/downgrade/cancel, booking confirm/cancel, claims or loan processing
>    - Fields and enums: `status`, `state`, `stage`, `step`, `OrderStatus`, `ApprovalState`; methods `setStatus(...)`, `transition`, `approve`, `confirm`, `ship`, `complete`, `cancel`, `reopen`; frameworks: Spring State Machine, Camunda/Flowable, Temporal, XState, AASM, django-fsm
>
> 5. **One-time artifacts and idempotency**: vouchers, gift-card redemption, invite codes, magic links, reward or referral claims, OTP-gated actions (the action after the OTP, not the OTP check), idempotency keys, provider event IDs
>    - Names: `redeem`, `claim`, `consume`, `used`, `usedAt`, `redeemed`, `usageCount`, `maxUses`, `idempotencyKey`, `Idempotency-Key`, `eventId`
>
> 6. **Usage limits, plans, and entitlements**: per-user/per-day limits, free trials, plan tiers, transaction or withdrawal limits, max items per order, referral caps
>    - Names: `plan`, `tier`, `subscription`, `trial`, `entitlement`, `maxPerUser`, `dailyLimit`, `isPremium`, `canUse`
>    - Also record the **frontend counterpart** if visible — Angular `canActivate` guards, form `Validators.min/max`, `[disabled]` buttons, `@if`/`*ngIf` on premium features — so Phase 2 can confirm the server enforces the same rule
>
> 7. **Non-HTTP entry points that mutate the same state**: `@KafkaListener`, `@RabbitListener`, `@JmsListener`, `@SqsListener`, BullMQ processors, NestJS `@EventPattern`/`@MessagePattern`, Celery tasks, `@Scheduled`/Quartz/cron jobs, batch imports, GraphQL mutations, gRPC handlers
>
> For every operation, also note structural concurrency markers if present: `@Transactional` (and its `isolation`), `@Lock`, `@Version`, `FOR UPDATE`, `select_for_update`, `$transaction`, `lockForUpdate`, unique constraints on related tables.
>
> **What to skip** (not business-critical for this skill):
> - Pure read-only endpoints (product listings, order history) unless they issue a value later trusted on write (e.g., a quote token)
> - Profile or preference updates that touch no money, stock, state, limit, or one-time field
> - Authentication flows themselves (login, password reset, OTP verification) — those belong to sast-authn
> - Static content, health checks, metrics endpoints
>
> **Output format** — write to `sast/businesslogic-recon.md`:
>
> ```markdown
> # Business Logic Recon: [Project Name]
>
> ## Summary
> Found [N] business-critical operations.
> Domain: [e.g., "e-commerce checkout + customer wallet" / "B2B payment approval workflow"]
>
> ## Business-Critical Operations
>
> ### 1. [Descriptive name — e.g., "Checkout creates order and charges card"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Function / endpoint**: [`METHOD /path`, or consumer/job name + handler method]
> - **Category**: [money movement / pricing & discounts / inventory & quotas / workflow & state / one-time artifact / limits & plans]
> - **Entity / aggregate**: [e.g., `Order`, `Account`, `Voucher`]
> - **State fields involved**: [e.g., `Order.status`, `Order.total`, `Product.stock`, `Voucher.redeemedAt`]
> - **Client-supplied values**: [every request field the operation reads — e.g., `productId`, `quantity`, `unitPrice`, `couponCode`; or "none"]
> - **Server-side lookups**: [authoritative values loaded from DB/config — e.g., "Product price via productRepository.findById"; or "none observed"]
> - **Persistence call(s)**: [e.g., `orderRepository.save(order)`, `UPDATE accounts SET balance = ?`, `prisma.wallet.update`]
> - **Concurrency markers**: [e.g., "@Transactional (default isolation), no lock" / "@Lock(PESSIMISTIC_WRITE)" / "none"]
> - **Related steps / frontend checks**: [preceding and following workflow steps; Angular guard or validator if any]
> - **Code snippet**:
>   ```
>   [the handler and the key state mutation]
>   ```
>
> [Repeat for each operation]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/businesslogic-recon.md`. If the recon found **zero business-critical operations** (the summary reports "Found 0" or the "Business-Critical Operations" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/businesslogic-results.md` and stop:

```markdown
# Business Logic Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one business-critical operation.

### Phase 2: Verify — Abuse-Path Analysis (Batched)

After Phase 1 completes, read `sast/businesslogic-recon.md` and split the operations into **batches of up to 3 operations each**. Launch **one subagent per batch in parallel**. Each subagent verifies only its assigned operations and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/businesslogic-recon.md` and count the numbered operation sections under "Business-Critical Operations" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 operations → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those operation sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned operations.
5. Each subagent writes to `sast/businesslogic-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Spring Boot with JPA and an Angular frontend, include all three "Java — Spring Boot" examples and the "TypeScript — Angular (frontend-only enforcement)" example. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned business-critical operation, determine whether an authenticated user can violate a business invariant — pay less than the real price, obtain money, credit, or stock they are not entitled to, skip a required workflow step, use a single-use artifact more than once, or exceed a limit. Our goal is to find business logic flaws. Write results to `sast/businesslogic-batch-[N].md`.
>
> **Your assigned operations** (from the recon phase):
>
> [Paste the full text of the assigned operation sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand the domain, the transaction management (`@Transactional`, `$transaction`, `transaction.atomic`), the database engine and its default isolation level, and how workflow steps relate to each other. Read related code as needed (preceding workflow steps, repositories, sibling consumers, frontend counterparts), but do not add new operations.
>
> **Business logic reference — run every check that applies to the operation's category** (mark checks that clearly do not apply as N/A):
>
> **Check 1 — Client-trusted values**
> - Does the operation read `price`, `unitPrice`, `amount`, `total`, `discount`, `fee`, `tax`, `shipping`, `currency`, `exchangeRate`, `plan`, `tier`, `role`, `points`, or `status` from the request and use it in a calculation, a charge, or a persisted record?
> - Is the value **recomputed** server-side from authoritative data (catalog price, plan price table, coupon record)? Comparing the client value to a server value is acceptable only if a mismatch rejects the request.
> - Hidden form fields, "quote" objects, and values echoed back from an earlier response are client-controlled unless a server-side HMAC/signature is verified. A plan/tier chosen in the request must be backed by a verified payment or entitlement record.
>
> **Check 2 — Numeric abuse**
> - Are quantities and amounts validated server-side for negative, zero, fractional, huge, and non-numeric input? Mentally test `-1`, `0`, `0.001`, `2147483648`, `1e309`, `NaN`, `"1e3"`.
> - Java: `int`/`long` multiplication without `Math.multiplyExact` can overflow to a negative total; `double`/`float` money drifts; `BigDecimal` without a scale check allows sub-cent amounts that round in the user's favor. Bean Validation (`@Positive`, `@Min`, `@DecimalMin`, `@Digits`) runs only when the parameter has `@Valid`/`@Validated` (nested list elements need `@Valid` too).
> - JS/TS: `Number` loses precision above 2^53; `NaN > x` and `NaN < x` are both `false`, so `if (amount > balance) reject` lets `NaN` through; `"5" + 1 === "51"`; class-validator decorators are inert unless `ValidationPipe` is registered.
> - Negative line items reduce totals; a negative transfer reverses its direction; repeated rounding (salami) or a client-chosen currency/exchange rate changes the value moved.
>
> **Check 3 — Workflow / state-machine bypass**
> - Write down the intended sequence (e.g., create → pay → confirm → ship). Does this step verify, **from the persisted record**, that the entity is in the required prior state — not from a client flag or a session hint?
> - Are transitions validated against an allowed-transition table or a conditional update (`WHERE status = 'PAID'`), or does the endpoint accept any target status?
> - Can a finalized record (paid, shipped, approved, refunded, closed) be edited, reopened, or re-submitted? Can a requester approve their own request? Can the approved amount change after approval? Are preconditions checked **before** side effects (charge, payout, shipment, email)?
>
> **Check 4 — Race conditions / TOCTOU**
> - Is there a read → check → write sequence on a balance, stock, quota, counter, or `used` flag?
> - Is it protected by a row lock (`SELECT ... FOR UPDATE`, `@Lock(LockModeType.PESSIMISTIC_WRITE)`, `select_for_update()`, `with_for_update()`, `lockForUpdate()`, `with_lock`), optimistic locking (`@Version`, EF `[Timestamp]`, Rails `lock_version`) with failure handling, an atomic conditional update (`UPDATE ... SET balance = balance - ? WHERE id = ? AND balance >= ?` with an affected-rows check), a unique constraint, or `SERIALIZABLE` isolation with retry?
> - Spring pitfalls: `@Transactional` alone does not prevent lost updates — default isolation is the DB default (READ COMMITTED on PostgreSQL/Oracle/SQL Server, REPEATABLE READ snapshot reads on MySQL), and JPA dirty checking writes back the stale value. `@Transactional` on a `private` method or reached via self-invocation (`this.debit()`) is not proxied and runs without a transaction. Checked exceptions do not trigger rollback by default.
> - In-process locks (`synchronized`, `ReentrantLock`, a JS `Map` of in-flight keys) do not hold across multiple instances/pods. In Node.js every `await` between check and write lets other requests interleave. For distributed locks (Redis `SETNX`, Redisson, ShedLock), confirm the check and the write both happen inside the lock.
>
> **Check 5 — Replay / single-use enforcement**
> - Can the same voucher, invite, gift card, reward, refund, or OTP-gated action be executed twice, sequentially or concurrently? Is "used" set atomically with granting the benefit?
> - Payment callbacks/webhooks: is the signature verified over the raw body with the provider SDK (`Webhook.constructEvent`, `stripe.webhooks.constructEvent`, Adyen HMAC validation) **before** any state change? Is the event ID persisted with a unique constraint so a replay is a no-op? Are amount and currency compared against the server-side order rather than trusted from the payload?
> - A payment-success redirect (`/checkout/success?orderId=...`) must not mark an order paid without confirming with the provider. Client-supplied `Idempotency-Key` headers must be scoped to the user and stored atomically before the side effect.
>
> **Check 6 — Limit and quota enforcement**
> - Is every per-user, per-day, per-plan, or per-order limit enforced **on the server** for this operation? Angular guards, form validators, disabled buttons, hidden menu items, and conditional rendering are UI only.
> - Is the limit counter checked and incremented atomically (otherwise parallel requests exceed it)? Is the same limit enforced on every entry point that reaches this state (REST, GraphQL, message consumer, batch import, older API versions)?
> - Free trials: recorded as consumed and tied to an identity that cannot be trivially recreated? Does cancel-and-resubscribe restart the trial? Referrals: self-referral, referral of existing users, reward granted before the referee qualifies.
>
> **Check 7 — Cross-entity consistency**
> - Do combined entities belong together per the business rules: coupon ↔ tenant/product/campaign, refund ↔ payment of the same order, payment method ↔ payer? (Plain ownership — user A reading user B's order — is sast-idor; here focus on combining valid entities the rules say must not be combined.)
> - Are amounts, accounts, and prices in the same currency (or converted server-side with a server-side rate)? Is self-targeting blocked where forbidden or reward-farming: transfer to self, gift to self, approve own request, refer self?
> - Aggregate caps: cumulative refunds ≤ captured amount; total discount ≤ subtotal; coupon stacking limited.
>
> **Mitigations** (confirm they are effective, not merely present):
> - Server-side recomputation from authoritative data; validation that is actually wired in (`@Valid`, global `ValidationPipe`, serializer `is_valid()`); transition tables checked before side effects
> - Row locks, `@Version` with conflict handling, atomic conditional updates with affected-rows checks, unique constraints; signature-verified, deduplicated webhooks reconciled with the stored order
> - Frontend validation **never** counts as a mitigation
>
> **What this skill is NOT** — do not flag here: IDOR / object ownership (sast-idor), missing authentication or role checks (sast-missingauth), framework auto-binding of privileged entity fields (sast-massassignment), login brute force / OTP rate limiting (sast-authn), injection (sast-sqli, sast-xss, sast-ssti, sast-rce).
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: A concrete abuse path is proven from the code — a client-supplied value is used with no server-side recomputation or bound check, a transition runs with no precondition check, a webhook is processed without signature verification, or a check-then-act on a balance, stock, counter, or single-use flag has no lock, atomic update, or unique constraint.
> - **Likely Vulnerable**: The abuse is plausible but depends on deployment or concurrency timing — e.g., the race window depends on isolation level or instance count, a check exists on the REST path but not on a sibling consumer, or webhook verification is controlled by a configuration flag that may be off.
> - **Not Vulnerable**: The server recomputes or bounds the value, enforces the transition, uses an effective lock / atomic update / unique constraint, and the invariant holds on every entry point.
> - **Needs Manual Review**: The business intent is unclear — e.g., a negative quantity may be a legitimate return flow, a price override may be an intended B2B/admin feature, or the operation may be intentionally repeatable.
>
> **State the business assumption** you relied on in every finding (e.g., "Assumed customers must not set their own unit price", "Assumed a voucher is single-use per code"). If the classification depends on that assumption being true, say so.
>
> **Output format** — write to `sast/businesslogic-batch-[N].md`:
>
> ```markdown
> # Business Logic Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route, consumer, or function name]
> - **Check failed**: [e.g., "Check 4 — Race condition / TOCTOU" (list all that apply)]
> - **Issue**: [e.g., "Voucher redeemed flag checked and set in separate statements without lock"]
> - **Business assumption**: [The rule you assumed the business intends]
> - **Evidence trace**: [Step-by-step from entry point → client value or check → state mutation, citing lines; highlight the missing recomputation, bound, transition check, lock, or dedup]
> - **Impact**: [What an attacker gains — free goods, double credit, negative balance, skipped approval, unlimited trial]
> - **Remediation**: [Specific fix — recompute from catalog, @Min/@Max with @Valid, transition table, @Lock / conditional UPDATE, unique constraint, webhook signature + event dedup]
> - **Dynamic Test**:
>   ```
>   [Steps to demonstrate the abuse on the live app: endpoint, method, tampered field or concurrency setup,
>    expected evidence. Use placeholders like <USER_TOKEN>. Examples:
>    - Price tamper: curl -X POST https://app.example.com/api/checkout -H "Authorization: Bearer <USER_TOKEN>" -H "Content-Type: application/json" -d '{"items":[{"productId":"<PRODUCT_ID>","quantity":1,"unitPrice":0.01}]}' → total 0.01; retry with "quantity": -3
>    - Race: seq 20 | xargs -P 20 -I{} curl -s -o /dev/null -w "%{http_code}\n" -X POST https://app.example.com/api/vouchers/redeem -H "Authorization: Bearer <USER_TOKEN>" -H "Content-Type: application/json" -d '{"code":"<VOUCHER_CODE>"}' → more than one 200 (tighter timing: Burp Repeater "Send group in parallel" or Turbo Intruder single-packet attack)
>    - Replay: resend a captured webhook to /webhooks/payment, or send an unsigned forged "succeeded" event for <ORDER_ID> → paid / credited again
>    - Workflow skip: POST /api/orders, then POST /api/orders/<ORDER_ID>/ship without /pay → 200 and status SHIPPED]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route, consumer, or function name]
> - **Check failed**: [check number and name]
> - **Issue**: [What appears to be wrong]
> - **Business assumption**: [The rule you assumed]
> - **Evidence trace**: [Best-effort trace; mark uncertain steps]
> - **Concern**: [Why it remains a risk — e.g., "Exploitable only with >1 replica or under READ COMMITTED"]
> - **Remediation**: [Specific fix]
> - **Dynamic Test**:
>   ```
>   [parallel-request, tampering, or replay steps to attempt the abuse]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route, consumer, or function name]
> - **Reason**: [e.g., "Total recomputed from catalog; @Min(1) @Max(100) with @Valid; conditional UPDATE on stock"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route, consumer, or function name]
> - **Business assumption**: [The assumption you could not confirm]
> - **Uncertainty**: [e.g., "Negative quantity may be the intended return flow"]
> - **Suggestion**: [What to confirm with the product owner or trace manually]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/businesslogic-batch-*.md` file and merge them into a single `sast/businesslogic-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/businesslogic-batch-1.md`, `sast/businesslogic-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (operations analyzed = total operations from recon that were batched, i.e., sum of operations across batches).
4. Write the merged report to `sast/businesslogic-results.md` using this format:

```markdown
# Business Logic Analysis Results: [Project Name]

## Executive Summary
- Operations analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/businesslogic-results.md`, **delete all intermediate batch files** (`sast/businesslogic-batch-*.md`). Keep `sast/businesslogic-recon.md`.

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 operations per subagent**. If there are 1-3 operations total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned operations' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: inventory every business-critical operation with its entity, state fields, client-supplied values, persistence calls, and concurrency markers. Do not judge abusability in Phase 1 — that is Phase 2's job.
- **Phase 2 is purely verification**: for each assigned operation, run Checks 1-7 and decide whether a business invariant can be violated. Read related code freely, but do not add new operations.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Every finding must state the business assumption it relies on — business logic has no universal "bad sink", so the assumption is what makes the finding reviewable.
- Frontend validation never counts as enforcement: Angular form validators, route guards, `[disabled]` buttons, and hidden UI elements can all be bypassed by calling the API directly.
- The server must recompute prices, totals, discounts, and fees from catalog/plan data. A request DTO that carries `price` or `total` is a red flag even if the frontend computes it "correctly".
- `@Transactional` alone does not prevent lost updates or double redemption — it needs a row lock, `@Version`, an atomic conditional update, or a unique constraint. Also check for self-invocation and `private` methods that silently bypass the transactional proxy.
- Check every entry point that mutates the same state: REST controllers, GraphQL mutations, message consumers (`@KafkaListener`, `@RabbitListener`), and scheduled jobs (`@Scheduled`). A rule enforced in the controller but not in the consumer is still a flaw.
- Webhooks and payment callbacks are attacker-reachable: unsigned or non-deduplicated callbacks that change payment state are a direct path to free goods or double credit.
- Clean up intermediate files: delete all `sast/businesslogic-batch-*.md` files after the final `sast/businesslogic-results.md` is written. **Preserve** `sast/businesslogic-recon.md` — the orchestrator reuses it on later runs.
