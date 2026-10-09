---
name: sast-massassignment
description: >-
  Detect Mass Assignment (CWE-915) and JavaScript Prototype Pollution (CWE-1321)
  vulnerabilities in a codebase using a three-phase approach: recon (find bulk
  binding and deep-merge sites), batched verify (trace user input to those sites
  and check which sensitive fields are overwritable in parallel subagents, 3
  candidates each), and merge (consolidate batch results). Covers request bodies
  bound directly to persistence entities, generic copy/merge utilities, ORM
  create/update with whole payloads, all-fields serializers and forms, over-broad
  DTOs and mappers, GraphQL inputs mirroring entities, and recursive merges with
  user-controlled keys. Requires sast/architecture.md (run sast-analysis first).
  Outputs findings to sast/massassignment-results.md. Use when asked to find mass
  assignment, over-posting, auto-binding, BOPLA, or prototype pollution bugs.
---

# Mass Assignment & Prototype Pollution Detection

You are performing a focused security assessment to find mass assignment and prototype pollution vulnerabilities in a codebase. This skill uses a three-phase approach with subagents: **recon** (find bulk binding and deep-merge sites), **batched verify** (taint and field exposure analysis in parallel batches of 3), and **merge** (consolidate batch reports into one file).

**Prerequisites**: `sast/architecture.md` must exist. Run the analysis skill first if it doesn't.

---

## What is Mass Assignment

Mass assignment (also called over-posting or auto-binding) occurs when an application binds request data to a domain or persistence object in bulk — copying every key the client supplies onto the object — instead of copying an explicit allowlist of fields. An attacker adds fields the UI never sends (`role`, `isAdmin`, `balance`, `ownerId`, `tenantId`, `id`) and the framework silently sets them, enabling privilege escalation, ownership or tenant takeover, balance/price manipulation, and bypass of verification workflows. Prototype pollution is the JavaScript variant: a recursive merge or path-set with user-controlled keys writes through `__proto__` or `constructor.prototype` into `Object.prototype`, injecting properties into every object in the process.

This maps to OWASP A08:2021 Software and Data Integrity Failures (CWE-915 Improperly Controlled Modification of Dynamically-Determined Object Attributes; CWE-1321 Prototype Pollution) and is commonly referenced as OWASP API3:2023 Broken Object Property Level Authorization.

The core pattern: *user-controlled request data is bound in bulk to an object whose security-sensitive fields are not excluded, and that object is persisted or used in an authorization decision.*

### What Mass Assignment IS

- A JPA entity used as `@RequestBody` or `@ModelAttribute` and then saved: `userRepository.save(user)` where `User` has `role`
- Whole-payload ORM calls: `User.create(req.body)`, `findByIdAndUpdate(id, req.body)`, `prisma.user.update({ data: req.body })`, `User::create($request->all())`
- Generic copy utilities onto entities: `BeanUtils.copyProperties(req, entity)`, `Object.assign(entity, req.body)`, `objectMapper.readerForUpdating(entity)`, `setattr` loops
- Serializers/forms exposing every field: DRF `fields = '__all__'` without `read_only_fields`, Laravel `$guarded = []`, Rails `permit!`
- Overwriting `id` / `ownerId` / `tenantId` through bulk binding so the write targets or reassigns another record
- Nested bindings reaching child entities: `{"account": {"balance": 1000000}}`, `roles[0]=ADMIN`
- Prototype pollution: `_.merge({}, req.body)` with `{"__proto__": {"isAdmin": true}}`

### What Mass Assignment is NOT

Do not flag these as mass assignment:

- **IDOR**: Changing an explicit identifier (`/api/orders/1002`, `?account_id=789`) used as a lookup key to reach another user's object → covered by **sast-idor**. Report here only when the identifier is overwritten through bulk binding of the payload onto the entity.
- **Missing authentication / function-level authorization**: Endpoint with no auth, or a regular user calling an admin endpoint → covered by **sast-missingauth**
- **Business logic abuse with legitimately exposed fields**: Negative `quantity`, coupon reuse, out-of-range values in fields the endpoint is designed to accept → covered by **sast-businesslogic**
- **Unsafe deserialization to RCE**: Jackson default typing / `@JsonTypeInfo(use = Id.CLASS)`, `ObjectInputStream`, `pickle`, unsafe YAML → covered by **sast-rce**
- **Excessive data exposure**: Returning too many fields in responses (e.g., serializing `passwordHash`) — response-side issue, out of scope for this skill
- **Injection through a bound value**: A bound field later concatenated into SQL → covered by **sast-sqli**

### Patterns That Prevent Mass Assignment

When you see these patterns, the code is likely **not vulnerable**:

**1. Dedicated input DTO with an explicit field allowlist (most common fix)**
```
# Java — request record containing only editable fields, copied explicitly
public record UpdateProfileRequest(String displayName, String email) {}
user.setDisplayName(req.displayName());

# TypeScript — NestJS whitelisting ValidationPipe + narrow DTO
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));

# Node.js — pick allowlisted keys before persistence
const { displayName, bio } = req.body;
await prisma.user.update({ where: { id: req.user.id }, data: { displayName, bio } });
```

**2. Framework-level allowlists and read-only markers**
```
# Spring MVC / Jackson / MapStruct
@InitBinder void init(WebDataBinder b) { b.setAllowedFields("displayName", "email"); }
@JsonProperty(access = JsonProperty.Access.READ_ONLY) private Role role;
@BeanMapping(ignoreByDefault = true) @Mapping(target = "displayName", source = "displayName")

# Rails / Laravel / Django REST Framework / ASP.NET Core
params.require(:user).permit(:name, :email)
protected $fillable = ['name', 'email'];
read_only_fields = ['id', 'is_staff']
await TryUpdateModelAsync(user, "", u => u.DisplayName, u => u.Email);
```

**3. Server-side overwrite of sensitive fields after binding**
```
# Java — the server value must be written LAST
BeanUtils.copyProperties(req, order);
order.setOwnerId(currentUser.getId());

# JavaScript — spread order decides who wins
const data = { ...req.body, ownerId: req.user.id, role: 'USER' };  // safe for ownerId/role only
const bad  = { ownerId: req.user.id, ...req.body };                // VULNERABLE: body overrides
```

**4. Prototype-pollution-safe merging (JavaScript)**
```
# Skip dangerous keys, use null-prototype targets, prefer Map for user-keyed data
if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
const target = Object.create(null);
# Patched libraries (lodash >= 4.17.21, jQuery >= 3.4.0); hardening: node --disable-proto=delete
```

---

## Vulnerable vs. Secure Examples

### Java — Spring Boot

```java
// VULNERABLE: JPA entity used directly as @RequestBody — client can send "role", "enabled", "balance"
@PutMapping("/api/users/me")
public User updateMe(@RequestBody User user, Authentication auth) {
    user.setId(currentUserId(auth));          // id pinned, but every other column is client-controlled
    return userRepository.save(user);
}

// VULNERABLE: @ModelAttribute form binding onto an entity (every property with a setter binds)
@PostMapping("/register")
public String register(@ModelAttribute User user) {
    userRepository.save(user);                // ?role=ADMIN&enabled=true&account.balance=1e9 also bind
    return "redirect:/login";
}

// VULNERABLE: BeanUtils.copyProperties copies every same-named property, including sensitive ones
@PatchMapping("/api/accounts/{id}")
public Account patch(@PathVariable Long id, @RequestBody AccountUpdateRequest req) {
    Account acct = accountService.getOwned(id);
    BeanUtils.copyProperties(req, acct);      // AccountUpdateRequest also declares status, creditLimit
    return accountRepository.save(acct);
}

// VULNERABLE: MapStruct maps all same-named fields from a DTO that mirrors the entity
@Mapper(componentModel = "spring")
public interface UserMapper {
    void updateEntity(UserDto dto, @MappingTarget User user);   // UserDto has roles, enabled, tenantId
}

// VULNERABLE: Jackson merges raw JSON onto a loaded entity (typical PATCH implementation)
@PatchMapping("/api/profiles/{id}")
@Transactional
public Profile patch(@PathVariable Long id, @RequestBody JsonNode body) throws IOException {
    Profile p = profileService.getOwned(id);
    objectMapper.readerForUpdating(p).readValue(body);   // same for objectMapper.updateValue(p, body)
    return p;                                            // managed entity — flushed on commit, no save() needed
}

// SECURE: dedicated request record + explicit copy onto the loaded entity
public record UpdateProfileRequest(@Size(max = 80) String displayName, @Email String email) {}
@PutMapping("/api/users/me")
public UserResponse updateMe(@Valid @RequestBody UpdateProfileRequest req, Authentication auth) {
    User user = userRepository.findById(currentUserId(auth)).orElseThrow();
    user.setDisplayName(req.displayName());
    user.setEmail(req.email());
    return UserResponse.from(userRepository.save(user));
}

// SECURE: MapStruct allowlist — nothing is mapped unless listed
@Mapper(componentModel = "spring")
public interface UserMapper {
    @BeanMapping(ignoreByDefault = true)
    @Mapping(target = "displayName", source = "displayName")
    @Mapping(target = "email", source = "email")
    void updateEntity(UpdateProfileRequest req, @MappingTarget User user);
}

// SECURE (defense in depth when an entity must be bound): read-only markers + binder allowlist
@Entity
@JsonIgnoreProperties(value = {"id", "roles", "enabled", "balance"}, allowGetters = true)
public class User { /* ... */ }
@InitBinder("user")
void initBinder(WebDataBinder binder) { binder.setAllowedFields("displayName", "email"); }
```

### TypeScript / Node.js — Express (Mongoose, Sequelize, Prisma, TypeORM)

```typescript
// VULNERABLE: Mongoose — whole body into create / update (strict mode only drops keys NOT in the schema)
app.post('/api/users', async (req, res) => res.json(await User.create(req.body)));
await User.findByIdAndUpdate(req.user.id, req.body, { new: true });

// VULNERABLE: Sequelize update without `fields`; TypeORM Object.assign onto an entity
const order = await Order.findByPk(req.params.id);
await order.update({ ...req.body });                       // status, total, userId writable
const user = await userRepo.findOneByOrFail({ id: req.user.id });
Object.assign(user, req.body);                             // role, isVerified, tenantId writable
await userRepo.save(user);

// VULNERABLE: Prisma — request body as `data`; spread puts server values FIRST so body wins
await prisma.user.update({ where: { id: req.user.id }, data: req.body });
await prisma.user.create({ data: { role: 'USER', ...req.body, password: hash } });

// SECURE: schema that strips/rejects unknown keys, then persist only parsed data
const UpdateMe = z.object({ displayName: z.string().max(80), bio: z.string().max(500) }).strict();
app.put('/api/users/me', auth, async (req, res) => {
  const data = UpdateMe.parse(req.body);                   // .passthrough() would be VULNERABLE
  res.json(await prisma.user.update({ where: { id: req.user.id }, data }));
});

// SECURE: Sequelize `fields` allowlist / explicit pick for Mongoose
await order.update(req.body, { fields: ['shippingAddress', 'note'] });
const { displayName, bio } = req.body;
await User.findByIdAndUpdate(req.user.id, { displayName, bio }, { runValidators: true });
```

### TypeScript — NestJS

```typescript
// VULNERABLE: ValidationPipe without whitelist — TS types are erased at runtime, extra keys pass through
app.useGlobalPipes(new ValidationPipe());                          // main.ts
@Patch('me')
update(@Req() req, @Body() dto: UpdateUserDto) {                   // client adds "roles": ["admin"]
  return this.usersRepo.update(req.user.id, dto);
}

// VULNERABLE: DTO derived from the entity, or the entity itself as @Body()
export class UpdateUserDto extends PartialType(User) {}            // inherits role, isVerified, tenantId
@Post() create(@Body() user: User) { return this.usersRepo.save(user); }

// SECURE: whitelist + forbidNonWhitelisted, narrow DTO (PickType or hand-written)
app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true }));
export class UpdateUserDto extends PickType(User, ['displayName', 'email'] as const) {}
// (or a hand-written DTO — with whitelist on, only properties carrying class-validator decorators survive)
```

### Python — Django / Django REST Framework

```python
# VULNERABLE: every model field writable through the serializer
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = '__all__'                     # is_staff, is_superuser, groups writable via PUT /api/me

# VULNERABLE: ModelForm denylist — any field added later is writable automatically
class AccountForm(forms.ModelForm):
    class Meta:
        model = Account
        exclude = ['owner']                    # credit_limit, status still bound

# SECURE: explicit fields + read_only_fields
class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['id', 'username', 'email', 'first_name', 'is_staff']
        read_only_fields = ['id', 'username', 'is_staff']
```

### Python — Flask / SQLAlchemy

```python
# VULNERABLE: constructor kwargs and setattr loop from request JSON
db.session.add(User(**request.json))           # POST /api/users — role="admin" accepted

for key, value in request.json.items():        # PATCH /api/users/me
    setattr(current_user, key, value)          # is_admin, balance, id

# SECURE: allowlist of editable attributes
EDITABLE = {'display_name', 'bio'}
for key in EDITABLE & request.json.keys():
    setattr(current_user, key, request.json[key])
```

### Go — net/http / Gin + GORM

```go
// VULNERABLE: decode the request straight into the GORM model, then Save (writes every column)
var u models.User                                    // has Role, IsAdmin, Balance
json.NewDecoder(r.Body).Decode(&u)                   // same for c.ShouldBindJSON(&u) in Gin
u.ID = currentUserID(r)
db.Save(&u)

// VULNERABLE: decoded map passed to Updates (every key becomes a column update)
var fields map[string]interface{}
json.NewDecoder(r.Body).Decode(&fields)
db.Model(&models.User{}).Where("id = ?", uid).Updates(fields)

// SECURE: narrow input struct, unknown fields rejected, explicit column allowlist
var in struct{ DisplayName, Bio string }
dec := json.NewDecoder(r.Body)
dec.DisallowUnknownFields()
if err := dec.Decode(&in); err != nil { http.Error(w, "bad request", http.StatusBadRequest); return }
db.Model(&models.User{ID: uid}).Select("DisplayName", "Bio").
    Updates(models.User{DisplayName: in.DisplayName, Bio: in.Bio})
```

### PHP — Laravel

```php
// VULNERABLE: unguarded model + all request input
class User extends Model { protected $guarded = []; }
$request->user()->update($request->all());           // is_admin, role, balance
User::create($request->all());
Model::unguard();                                    // also: forceFill()/forceCreate() bypass $fillable
$order->fill($request->input())->save();

// SECURE: $fillable allowlist + validated() / only()
class User extends Model { protected $fillable = ['name', 'email']; }
$request->user()->update($request->validated());     // UpdateProfileRequest (FormRequest) rules define allowed keys
$request->user()->update($request->only(['name', 'email']));
```

### C# — ASP.NET Core

```csharp
// VULNERABLE: EF Core entity bound directly from the body
[HttpPut("api/users/me")]
public async Task<IActionResult> UpdateMe([FromBody] User user) {
    user.Id = CurrentUserId();
    _db.Users.Update(user);                          // IsAdmin, Role, Balance overwritten
    await _db.SaveChangesAsync(); return Ok();
}

// VULNERABLE: TryUpdateModelAsync without an include list (binds every posted field)
var user = await _db.Users.FindAsync(id);
await TryUpdateModelAsync(user);

// SECURE: input model + explicit copy, or include-list overload
public record UpdateMeInput(string DisplayName, string Email);
[HttpPut("api/users/me")]
public async Task<IActionResult> UpdateMe([FromBody] UpdateMeInput input) {
    var user = await _db.Users.FindAsync(CurrentUserId());
    (user.DisplayName, user.Email) = (input.DisplayName, input.Email);
    await _db.SaveChangesAsync(); return Ok();
}
await TryUpdateModelAsync(user, "", u => u.DisplayName, u => u.Email);
```

### Ruby on Rails

```ruby
# VULNERABLE: permit! / unsafe hash / raw params (raw params only work with permit_all_parameters = true or Rails < 4)
current_user.update(params.require(:user).permit!)
@account = Account.new(params[:account].to_unsafe_h)
current_user.update(params[:user])
params.require(:user).permit(:name, :email, :role, :admin, :organization_id)   # allowlist includes privileged attrs

# SECURE: strict allowlist; privileged attributes set server-side only
current_user.update(params.require(:user).permit(:name, :email))
```

### Prototype Pollution (JavaScript)

```javascript
// VULNERABLE: deep merge of request JSON (lodash < 4.17.12 merge/defaultsDeep, jQuery < 3.4.0 $.extend)
const settings = _.merge({}, defaults, req.body);       // body: {"__proto__": {"isAdmin": true}}
_.defaultsDeep(options, req.body);
$.extend(true, config, JSON.parse(userJson));

// VULNERABLE: hand-rolled recursive merge or path setter with user-controlled keys (any library version)
function merge(target, src) {
  for (const key in src) {
    if (typeof src[key] === 'object') merge(target[key] ??= {}, src[key]);
    else target[key] = src[key];
  }
}
setByPath(obj, req.body.path, req.body.value);          // path = "constructor.prototype.isAdmin"
// Gadgets elsewhere: if (user.isAdmin) {...}  |  res.render(view, opts)  |  spawn(cmd, args, opts)

// SECURE: reject dangerous keys, use null-prototype targets, validate shape before merging
const FORBIDDEN = new Set(['__proto__', 'constructor', 'prototype']);
function safeMerge(target, src) {
  for (const key of Object.keys(src)) {
    if (FORBIDDEN.has(key)) continue;
    const v = src[key];
    if (v && typeof v === 'object' && !Array.isArray(v)) safeMerge(target[key] ??= Object.create(null), v);
    else target[key] = v;
  }
}
const settings = { ...defaults, ...SettingsSchema.parse(req.body) };   // validated, shallow
```

---

## Execution

This skill runs in three phases using subagents. Pass the contents of `sast/architecture.md` to all subagents as context.

**Cache reuse**: If `sast/massassignment-recon.md` already exists, skip Phase 1 and reuse it. If `sast/sinks-index.md` exists, pass its `## sast-massassignment` section to the Phase 1 subagent as a starting list of candidate sites — the subagent must still search beyond it, since the index is regex-based and incomplete.

### Phase 1: Recon — Find Bulk Binding Sites

Launch a subagent with the following instructions:

> **Goal**: Find every location in the codebase where request-shaped data is bound to a domain or persistence object in bulk, or deep-merged / path-set into an object, instead of being copied field by field from an explicit allowlist. Write results to `sast/massassignment-recon.md`.
>
> **Context**: You will be given the project's architecture summary (and, if available, the `## sast-massassignment` section of `sast/sinks-index.md` as a starting list — search beyond it). Use it to understand the tech stack, web framework binding conventions, ORM/persistence layer, DTO/mapping layer, and validation configuration.
>
> **What to search for — bulk binding patterns**:
>
> Flag ANY place where an object of broad or unknown shape is bound, copied, or merged into an entity/model, or deep-merged with dynamic keys. You are not yet tracing whether the source is user-controlled or which fields are actually settable — that is Phase 2's job. You must, however, record the sensitive fields declared on the target type.
>
> 1. **Request body bound directly to a persistence entity**:
>    - Spring: controller parameters typed as an `@Entity` / `@Document` / `@Table` class with `@RequestBody`, `@ModelAttribute`, or no annotation; Spring Data REST `@RepositoryRestResource` / exported repositories (PUT/PATCH/POST on entities)
>    - NestJS / ASP.NET Core: `@Body() x: <Entity>` typed as a TypeORM/Mongoose/Prisma model class; `[FromBody]` / `[FromForm]` parameters typed as EF Core entities
>    - Go: `json.NewDecoder(r.Body).Decode(&model)`, `c.ShouldBindJSON(&model)`, `c.Bind(&model)` where the struct is a GORM model
>
> 2. **Generic copy/merge utilities from request objects to entities**:
>    - Java: `BeanUtils.copyProperties(src, entity)` (Spring and Apache), `PropertyUtils.copyProperties`, `ModelMapper.map(src, entity)`, Dozer, `objectMapper.updateValue(entity, src)`, `objectMapper.readerForUpdating(entity).readValue(...)`, `objectMapper.convertValue(map, Entity.class)`
>    - JS/TS: `Object.assign(entity, req.body)`, `{ ...entity, ...req.body }`, `_.assign` / `_.extend(entity, body)`, TypeORM `repo.merge(entity, body)`, `plainToInstance(Entity, req.body)` / `plainToClass`
>    - Python: `setattr(obj, k, v)` loops over request data, `obj.__dict__.update(data)`, `Model(**data)`
>    - C# / Ruby / PHP: `_db.Entry(e).CurrentValues.SetValues(input)`, AutoMapper `_mapper.Map(src, entity)`, `assign_attributes(params[...])`, `$model->fill(...)`, `forceFill(...)`
>
> 3. **ORM create/update called with the whole request payload**:
>    - Mongoose: `Model.create(req.body)`, `new Model(req.body)`, `findByIdAndUpdate(id, req.body)`, `findOneAndUpdate(filter, req.body)`, `updateOne(filter, req.body)`
>    - Sequelize: `Model.create(req.body)`, `instance.update(req.body)` without `fields`, `Model.update(req.body, { where })`
>    - Prisma: `prisma.<model>.create/update/upsert({ data: req.body })`, `data: { ...req.body }`, `data: args.input`
>    - TypeORM: `repo.save(req.body)`, `repo.create(req.body)`, `repo.insert(req.body)`, `repo.update(id, dto)`
>    - Django / SQLAlchemy: `Model.objects.create(**request.data)`, `.filter(...).update(**request.data)`, `Model(**request.json)`
>    - Laravel / Rails: `Model::create($request->all())`, `->update($request->all())`, `->fill($request->input())`, `$request->except([...])` (denylist); `Model.new(params[:x])`, `update(params[:x])`, `permit!`, `to_unsafe_h`, `permit_all_parameters = true`
>    - GORM / EF Core: `db.Save(&decoded)`, `db.Create(&decoded)`, `db.Model(...).Updates(decodedMap)`; `_db.Update(entity)` / `_db.Attach(entity)` with a bound entity, `TryUpdateModelAsync(entity)` without an include list
>
> 4. **Serializers / forms with all-fields or denylist configuration**:
>    - DRF `ModelSerializer` / Django `ModelForm` with `fields = '__all__'` or `exclude = [...]`; writable nested serializers
>    - Laravel models with `$guarded = []`, `$guarded = ['id']` only, or `Model::unguard()`; Rails `permit(...)` lists containing privileged attributes, `accepts_nested_attributes_for` on privileged associations
>    - NestJS `ValidationPipe` without `whitelist: true` (global in `main.ts` or per-route), or no ValidationPipe at all
>    - Mongoose schemas with `strict: false`; zod `.passthrough()`; Joi `allowUnknown: true`; pydantic `extra='allow'`
>    - Spring `@InitBinder` using `setDisallowedFields` (denylist) instead of `setAllowedFields`
>
> 5. **DTOs that include sensitive fields and are mapped wholesale to entities**:
>    - DTO classes that mirror the entity (same field set, `extends PartialType(Entity)`, `extends Entity`, Lombok `@Data` clones) and include sensitive fields
>    - MapStruct `@Mapper` methods with `@MappingTarget` or returning an entity, without `@Mapping(target = "...", ignore = true)` for sensitive fields and without `@BeanMapping(ignoreByDefault = true)`
>    - OpenAPI-generated request models (`*Request` / `*Dto`) whose schema exposes `role`, `status`, `ownerId`, etc. and are mapped to entities
>
> 6. **Deep merge / path-set with user-controlled keys (prototype pollution, JS/TS only)**:
>    - `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.set`, `_.setWith`, `_.zipObjectDeep`, `$.extend(true, ...)`, `deepmerge`, `merge-deep`, `dot-prop` / `object-path` `set`, `flat.unflatten`
>    - Hand-rolled recursive merge/clone/extend functions iterating `for...in` / `Object.keys` and recursing into objects; bracket assignment with dynamic keys inside loops over input (`obj[a][b] = value`)
>    - Client-side (Angular / browser): merges of `location.search`, `location.hash`, or `postMessage` data into config objects
>
> 7. **GraphQL input types that mirror entities**:
>    - Input types (`input UpdateUserInput { role: Role }`, `@InputType()` classes, Spring GraphQL `@Argument` typed as an entity) that include sensitive fields
>    - Resolvers/mutations that spread or copy the input into ORM calls: `prisma.user.update({ data: args.input })`, `repo.save({ ...input })`, `BeanUtils.copyProperties(input, entity)`
>
> **Sensitive fields on target** — for every site, open the target entity/model/DTO class (including superclasses, `@Embedded` / `@Embeddable` types, nested relations, and collections) and list fields resembling: `role`, `roles`, `isAdmin`, `admin`, `superuser`, `staff`, `permissions`, `authorities`, `scopes`, `groups`, `status`, `state`, `verified`, `emailVerified`, `kycStatus`, `enabled`, `active`, `locked`, `approved`, `balance`, `credit`, `creditLimit`, `price`, `amount`, `discount`, `fee`, `quota`, `ownerId`, `userId`, `accountId`, `tenantId`, `organizationId`, `createdBy`, `password`, `passwordHash`, `resetToken`, `apiKey`, `mfaEnabled`, `mfaSecret`, `plan`, `tier`, `id` / primary key, `version`. Include nested paths (e.g., `account.balance`, `roles[]`).
>
> **What to skip** (these are safe binding patterns — do not flag):
> - Binding into a narrow DTO whose fields are copied **one by one** into the entity (`entity.setName(dto.getName())`) — unless the DTO is then passed to a copy utility or mapper
> - ORM calls with an explicitly constructed object of allowlisted fields: `User.create({ name: body.name, email: body.email })`
> - Binding used only for filtering/search (`@ModelAttribute SearchCriteria`, query DTOs) that never reaches a create/update/merge — unless it is deep-merged (category 6)
> - Merges where the source is entirely server-side constants or configuration
> - Test, fixture, seed, and migration code
>
> **Output format** — write to `sast/massassignment-recon.md`:
>
> ```markdown
> # Mass Assignment Recon: [Project Name]
>
> ## Summary
> Found [N] bulk binding sites.
>
> ## Bulk Binding Sites
>
> ### 1. [Descriptive name — e.g., "User entity bound as @RequestBody in UserController.updateMe"]
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [`METHOD /path` or function name]
> - **Binding pattern**: [category + pattern, e.g., "(1) @RequestBody JPA entity", "(2) BeanUtils.copyProperties", "(6) _.merge with request JSON"]
> - **Target type / model**: [class/model/schema name + file path]
> - **Persistence call**: [e.g., `userRepository.save(user)` (line N) / `prisma.user.update` / "managed entity in @Transactional" / "none found" / "N/A — prototype pollution"]
> - **Sensitive fields on target**: [e.g., `role`, `enabled`, `balance`, `tenantId`, `id`, nested `account.creditLimit` — or "none identified"]
> - **Code snippet**:
>   ```
>   [the binding + persistence/usage code]
>   ```
>
> [Repeat for each site]
> ```

### After Phase 1: Check for Candidates Before Proceeding

After Phase 1 completes, read `sast/massassignment-recon.md`. If the recon found **zero bulk binding sites** (the summary reports "Found 0" or the "Bulk Binding Sites" section is empty or absent), **skip Phase 2 entirely**. Instead, write the following content to `sast/massassignment-results.md` and stop:

```markdown
# Mass Assignment Analysis Results

No vulnerabilities found.
```

Only proceed to Phase 2 if Phase 1 found at least one bulk binding site.

### Phase 2: Verify — Taint and Field Exposure Analysis (Batched)

After Phase 1 completes, read `sast/massassignment-recon.md` and split the binding sites into **batches of up to 3 sites each**. Launch **one subagent per batch in parallel**. Each subagent analyzes only its assigned sites and writes results to its own batch file.

**Batching procedure** (you, the orchestrator, do this — not a subagent):

1. Read `sast/massassignment-recon.md` and count the numbered site sections under "Bulk Binding Sites" (### 1., ### 2., etc.).
2. Divide them into batches of up to 3. For example, 8 sites → 3 batches (1-3, 4-6, 7-8).
3. For each batch, extract the full text of those site sections from the recon file.
4. Launch all batch subagents **in parallel**, passing each one only its assigned sites.
5. Each subagent writes to `sast/massassignment-batch-N.md` where N is the 1-based batch number.
6. Identify the project's primary language/framework from `sast/architecture.md` and select **only the matching examples** from the "Vulnerable vs. Secure Examples" section above. For example, if the project uses Spring Boot with an Angular frontend, include the "Java — Spring Boot" examples, plus "Prototype Pollution (JavaScript)" if any category 6 site is in the batch. Include these selected examples in each subagent's instructions where indicated by `[TECH-STACK EXAMPLES]` below.

Give each batch subagent the following instructions (substitute the batch-specific values):

> **Goal**: For each assigned bulk binding site, determine whether user-controlled request data reaches the binding, which fields of the target can actually be set, and whether any settable field is security-sensitive and persisted or used in an authorization decision. Our goal is to find mass assignment and prototype pollution vulnerabilities. Write results to `sast/massassignment-batch-[N].md`.
>
> **Your assigned binding sites** (from the recon phase):
>
> [Paste the full text of the assigned site sections here, preserving the original numbering]
>
> **Context**: You will be given the project's architecture summary. Use it to understand request entry points, the binding/validation layer, mapping conventions, and how data flows into persistence.
>
> **Mass assignment reference — answer these questions for each site**:
>
> 1. **Does user-controlled data reach the binding?** Trace the source object backwards to its origin:
>    - Request body (JSON / XML / form): `@RequestBody`, `@ModelAttribute`, `req.body`, `request.data`, `request.json`, `request.POST`, `$request->all()`, `params[:x]`, `[FromBody]`, `[FromForm]`, `c.ShouldBindJSON`
>    - Query string / path: `@RequestParam Map<String, ...>`, `req.query` (including nested parsing such as `?user[role]=admin`), `request.GET`
>    - GraphQL input arguments, WebSocket messages, message-queue payloads (`@KafkaListener`, `@RabbitListener`) whose producer is user-influenced, and uploaded JSON/CSV/YAML imports
>    - Indirect flow: the request object passed through services, wrapped in another DTO, or stored and later copied — follow every hop and check all call sites
>    - Server-side only (config, constants, internal data with no user influence) → NOT exploitable
>
> 2. **Which fields of the target can actually be set?** Inspect the target class/model (superclasses, embedded types, nested relations, collections) and the binding configuration:
>    - Jackson: settable if there is a setter, a public field, field visibility, or a `@JsonCreator` / record constructor parameter. Blocked by `@JsonIgnore`, `@JsonProperty(access = READ_ONLY)`, `@JsonIgnoreProperties({...})` (unless `allowSetters = true`), `@JsonView` applied to the request body. `FAIL_ON_UNKNOWN_PROPERTIES` only concerns unknown keys, not sensitive known ones
>    - Spring `@ModelAttribute` / data binding: every property with a setter is bindable, including nested paths (`account.balance=...`, `roles[0].name=...`), unless `@InitBinder` `setAllowedFields` restricts it; `setDisallowedFields` is a denylist — check it is complete
>    - MapStruct / ModelMapper / BeanUtils: which target properties are mapped — `@Mapping(target = "x", ignore = true)`, `@BeanMapping(ignoreByDefault = true)`; ModelMapper `skip()` / `STRICT`; `BeanUtils.copyProperties(src, target, ignoreProperties...)` is a denylist
>    - JS/TS: NestJS `ValidationPipe({ whitelist: true, forbidNonWhitelisted: true })` — global or per-route; without `whitelist`, extra keys survive. class-transformer `@Exclude()` / `excludeExtraneousValues`; zod default strip or `.strict()` vs `.passthrough()`; Joi `stripUnknown`; Mongoose `strict` (default true drops keys NOT in the schema — sensitive keys IN the schema remain settable); Sequelize `fields`; Prisma — every scalar and relation in `data` is writable, including nested `connect` / `create`
>    - Python: DRF `fields` / `exclude` / `read_only_fields` / `read_only=True` / `extra_kwargs`; Django ModelForm `fields`; pydantic fields and `extra`
>    - Laravel / Rails: `$fillable` (allowlist) vs `$guarded` (denylist), `Model::unguard()`, `forceFill` / `forceCreate`, FormRequest `validated()` returns only validated keys; the `permit(...)` list, `permit!`, `accepts_nested_attributes_for`, `attr_readonly`
>    - Go: fields tagged `json:"-"` are not decoded; exported fields without tags decode by case-insensitive name; GORM `Save` writes all columns, `Updates(struct)` writes non-zero fields, `Updates(map)` writes every key; `Select(...)` / `Omit(...)` restrict columns
>    - C#: `[BindNever]`, `[Bind("...")]`, `[JsonIgnore]`, private/init-only setters, `TryUpdateModelAsync` include expressions
>
> 3. **Is any settable field security-sensitive?** Classify each one: **privilege** (`role`, `authorities`, `isAdmin`, `permissions`, `plan`), **ownership / tenant** (`ownerId`, `userId`, `tenantId`, `organizationId`, `createdBy`), **money / limits** (`balance`, `creditLimit`, `price`, `discount`, `quota`), **verification / workflow state** (`verified`, `emailVerified`, `kycStatus`, `status`, `approved`, `enabled`, `locked`), **credentials** (`password` / `passwordHash` bypassing hashing or current-password checks, `resetToken`, `apiKey`, `mfaEnabled`), or **primary key** (`id`, `version` — overwriting `id` before `save()` / `merge()` can update or hijack another record).
>
> 4. **Is the changed field persisted or used afterwards?** Confirm the bound object reaches `save` / `update` / `merge` / `commit` / `SaveChanges`, or that the field is read in an authorization or business decision in the same request (`if (user.isAdmin)`, `order.getPrice()` used to charge). JPA note: a managed entity modified inside a `@Transactional` method is flushed on commit even without an explicit `save()`.
>
> 5. **Mitigations** (check even if user input reaches the binding):
>    - Dedicated input DTO containing only allowlisted, non-sensitive fields, copied explicitly
>    - Server overwrite **after** binding: `entity.setOwnerId(currentUser.getId())`, `{ ...req.body, ownerId: req.user.id }`. Ordering matters — `{ ownerId: req.user.id, ...req.body }` and overwrites performed **before** the copy are NOT mitigations. An overwrite only protects the fields it touches; check every other sensitive field
>    - `@InitBinder` `setAllowedFields(...)`, Rails `permit` with only safe attributes, Laravel `$fillable`, DRF `read_only_fields`, NestJS `whitelist`, MapStruct ignores / `ignoreByDefault`
>    - Explicit checks that reject changes to sensitive fields (e.g., `if (dto.getRole() != null && !isAdmin) throw ...`)
>    - Frontend form omission (an Angular/React form not rendering the field) is **not** a mitigation — the API can be called directly
>
> **Prototype pollution reference** (category 6 sites, JS/TS):
> - Are the merged keys or paths user-controlled (JSON body, nested query parsing, GraphQL JSON scalar, `postMessage`, URL hash)? `JSON.parse` creates `__proto__` as an own enumerable key.
> - Is the merge recursive, or a path-set with a user-controlled path? A shallow `Object.assign` / spread only changes the target's own prototype, not `Object.prototype`.
> - Are `__proto__`, `constructor`, and `prototype` filtered? Is the target created with `Object.create(null)`? Is the library version patched (check `package.json` and the lockfile: lodash >= 4.17.21, jQuery >= 3.4.0, current `deepmerge` / `dot-prop` / `object-path`)?
> - Is there a gadget — code reading a property that could be inherited: `if (obj.isAdmin)`, `child_process` options (`shell`, `env`), template engine options (`outputFunctionName`, `escapeFunction`, `client`), `res.render(view, options)`, `config.x || default`? No gadget identified → Likely Vulnerable, not Vulnerable.
>
> **Vulnerable vs. Secure examples for this project's tech stack**:
>
> [TECH-STACK EXAMPLES]
>
> **Classification**:
> - **Vulnerable**: User input reaches the binding AND at least one security-sensitive field is settable AND that field is persisted or used in an authorization/business decision. For prototype pollution: user-controlled keys reach an unfiltered recursive merge/path-set AND a gadget is identified.
> - **Likely Vulnerable**: User input is bound to an entity with sensitive fields, but persistence or usage is not fully proven (opaque service layer, settability depends on runtime mapper/Jackson configuration, denylist that appears incomplete); or prototype pollution without a confirmed gadget.
> - **Not Vulnerable**: The source is server-side only, OR an allowlisting DTO/configuration excludes every sensitive field, OR only harmless fields are settable, OR the server overwrites every sensitive field after binding.
> - **Needs Manual Review**: The target type is dynamic (generics, `Map<String, Object>` applied via reflection), the mapping layer is opaque (generated code not present, custom reflection utility), or the binding configuration cannot be located.
>
> **Output format** — write to `sast/massassignment-batch-[N].md`:
>
> ```markdown
> # Mass Assignment Batch [N] Results
>
> ## Findings
>
> ### [VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "JPA entity `User` bound as `@RequestBody` and saved; client can set `role`"]
> - **Taint trace**: [Step-by-step from request source → binding → persistence / authorization use]
> - **Overwritable sensitive fields**: [field — consequence, e.g., `role` (escalate to ADMIN), `tenantId` (move record to another tenant)]
> - **Impact**: [What an attacker can do — privilege escalation, ownership takeover, free credit, skip verification, etc.]
> - **Remediation**: [Dedicated DTO with allowlisted fields, framework allowlist, or server overwrite after binding]
> - **Dynamic Test**:
>   ```
>   [Send the normal request plus one sensitive field, then read back to confirm it persisted. Use <USER_TOKEN> placeholders.
>    Example: curl -X PUT /api/users/me -H 'Content-Type: application/json' -d '{"displayName":"x","role":"ADMIN"}'
>    then GET /api/users/me and expect "role":"ADMIN".
>    Prototype pollution: -d '{"__proto__":{"isAdmin":true}}' or '{"constructor":{"prototype":{"isAdmin":true}}}',
>    then call an endpoint that reads the polluted property]
>   ```
>
> ### [LIKELY VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Issue**: [e.g., "Entity bound and passed to an opaque service; persistence not proven"]
> - **Taint trace**: [Best-effort trace; mark uncertain steps]
> - **Overwritable sensitive fields**: [Suspected fields]
> - **Concern**: [Why it remains a risk]
> - **Remediation**: [Replace bulk binding with an allowlisted DTO]
> - **Dynamic Test**:
>   ```
>   [payload adding the suspected sensitive field(s), plus how to observe the effect]
>   ```
>
> ### [NOT VULNERABLE] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Reason**: [e.g., "Narrow DTO with explicit copy" or "ValidationPipe whitelist strips extra keys" or "ownerId/role overwritten after copy; no other sensitive fields"]
>
> ### [NEEDS MANUAL REVIEW] Descriptive name
> - **File**: `path/to/file.ext` (lines X-Y)
> - **Endpoint / function**: [route or function name]
> - **Uncertainty**: [Why settability or origin could not be determined]
> - **Suggestion**: [What to inspect manually — generated mapper, runtime ObjectMapper config, reflection helper]
> ```

### Phase 3: Merge — Consolidate Batch Results

After **all** Phase 2 batch subagents complete, read every `sast/massassignment-batch-*.md` file and merge them into a single `sast/massassignment-results.md`. You (the orchestrator) do this directly — no subagent needed.

**Merge procedure**:

1. Read all `sast/massassignment-batch-1.md`, `sast/massassignment-batch-2.md`, ... files.
2. Collect all findings from each batch file and combine them into one list, preserving the original classification and all detail fields.
3. Count totals across all batches for the executive summary (binding sites analyzed = total sites from recon that were batched, i.e., sum of sites across batches).
4. Write the merged report to `sast/massassignment-results.md` using this format:

```markdown
# Mass Assignment Analysis Results: [Project Name]

## Executive Summary
- Binding sites analyzed: [total across all batches]
- Vulnerable: [N]
- Likely Vulnerable: [N]
- Not Vulnerable: [N]
- Needs Manual Review: [N]

## Findings

[All findings from all batches, grouped by classification:
 VULNERABLE first, then LIKELY VULNERABLE, then NEEDS MANUAL REVIEW, then NOT VULNERABLE.
 Preserve every field from the batch results exactly as written.]
```

5. After writing `sast/massassignment-results.md`, **delete all intermediate batch files** (`sast/massassignment-batch-*.md`).

---

## Important Reminders

- Read `sast/architecture.md` and pass its content to all subagents as context.
- Phase 2 must run AFTER Phase 1 completes — it depends on the recon output.
- Phase 3 must run AFTER all Phase 2 batches complete — it depends on all batch outputs.
- Batch size is **3 binding sites per subagent**. If there are 1-3 sites total, use a single subagent. If there are 10, use 4 subagents (3+3+3+1).
- Launch all batch subagents **in parallel** — do not run them sequentially.
- Each batch subagent receives only its assigned sites' text from the recon file, not the entire recon file. This keeps each subagent's context small and focused.
- **Phase 1 is purely structural**: flag every bulk binding, copy, or deep merge into an object and list the target's sensitive fields. Do not trace user input in Phase 1 — that is Phase 2's job.
- **Phase 2 is taint plus field exposure analysis**: a site is a real vulnerability only when user input reaches the binding AND a sensitive field is settable AND it is persisted or used.
- **An entity used as `@RequestBody` (or `@ModelAttribute`) is the #1 Spring pattern.** Check every controller parameter whose type is an `@Entity` / `@Document`, every `BeanUtils.copyProperties` / MapStruct / `readerForUpdating` onto an entity, and Spring Data REST exported repositories.
- **ID fields matter**: overwriting `id` (or a key / `@Version` field) through bulk binding can turn an update of your own record into an update of another record, or a create into an overwrite. This overlaps with IDOR — report it here when the cause is bulk binding of the payload; leave explicit ID lookups to sast-idor.
- **Nested objects and collections bind too**: `{"account":{"balance":1e9}}`, form paths like `account.balance=...`, `roles[0]=ADMIN`, Prisma nested `connect` / `create`, Rails `accepts_nested_attributes_for`, JPA relations with `cascade = MERGE` / `ALL`.
- **PATCH endpoints are highest risk**: partial updates tend to copy "whatever was sent" (`readerForUpdating`, `updateValue`, `Object.assign`, `Updates(map)`, `setattr` loops).
- **Check both create and update**: registration and sign-up flows often accept `role`, `verified`, or `tenantId` on create even when the update endpoint is locked down, and vice versa.
- Denylists decay: `exclude`, `$guarded`, `setDisallowedFields`, `ignoreProperties`, and `@JsonIgnoreProperties` miss sensitive fields added later. Treat a denylist that omits any sensitive field as at least Likely Vulnerable.
- TypeScript types and Angular form layouts are not runtime controls — an attacker sends raw JSON to the API directly. Only runtime stripping (whitelist pipes, schemas, explicit picks, allowlisted DTOs) counts.
- When in doubt, classify as "Needs Manual Review" rather than "Not Vulnerable". False negatives are worse than false positives in security assessment.
- Clean up intermediate files: delete all `sast/massassignment-batch-*.md` files after the final `sast/massassignment-results.md` is written. **Preserve** `sast/massassignment-recon.md` — the orchestrator reuses it on later runs.
