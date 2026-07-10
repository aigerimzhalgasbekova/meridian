# ADR 0003: Scoped assignments — global or one realm

**Status:** Accepted — 2026-07-09

## Context

Meridian is multi-tenant: the idp partitions users into realms. The console must
express "full admin of the engineering realm, nothing anywhere else" without minting a
realm-specific copy of every role. Options considered:

1. **Scope on the assignment** — roles stay scope-free; the binding says where it applies.
2. **Scope baked into the role** — `engineering-admin`, `finance-admin`, … per realm.
3. **Hierarchical scopes** — org → realm → resource trees with inheritance down the tree.

## Decision

Scope lives on the **assignment**: `{subject, role, scope}` where scope is global or
exactly one realm. Global covers every realm; a realm covers only itself. Roles are
scope-free, reusable objects.

## Rationale

- **Roles stay a catalog, not a combinatorial explosion.** One `realm-admin` role
  serves every realm; the realm count never touches the role table. Option 2 breaks at
  the second realm and makes "what can alice do" a string-parsing exercise.
- **Two-level scope matches the actual tenancy model.** The platform has exactly one
  partition dimension (realm). Hierarchical scope trees (option 3) are Zanzibar-shaped
  machinery for a hierarchy that does not exist here; the `Scope` struct is one field
  and can grow if the platform ever grows real hierarchy.
- **Authorization checks become scope-local.** `Check(alice, users:write, realm:finance)`
  ignores alice's engineering assignment entirely — scope isolation is enforced in one
  place, `Scope.covers`, and the trace records skipped assignments so the isolation is
  visible, not silent.

## The write rules the scope model produces

- **Role definitions are global objects**, so `roles:write` is checked at global
  scope. A realm-admin cannot create or edit roles: a role they authored would be
  assignable in *other* realms, which exceeds their authority.
- **Assignment writes are checked at the scope being granted or revoked.** This single
  rule is the whole tenancy boundary: alice (realm-admin of engineering) can assign
  `viewer` at `realm:engineering`, but assigning at `realm:finance` or globally is
  denied — verified in `TestAssignmentScopeEnforcement`.
- **User and session operations are checked at the target's realm** — an engineering
  realm-admin cannot disable a finance user or revoke their sessions.

## Consequences

- No cross-realm grants short of global; a two-realm admin is two assignments.
- A realm-admin can grant `realm-admin` in their own realm (delegation is allowed by
  design); they can never escalate to global because no realm-scoped check covers it.
- Realm names are free-form strings validated only at the idp; the console treats them
  opaquely.
