package store

// The Lua scripts below are the only writers of session state. Each one runs
// atomically inside Redis, which is what makes multi-node check-and-act
// sequences safe: two nodes racing the same user's cap, or a touch racing a
// revoke, serialize on the single point of truth instead of interleaving.
//
// The clock ("now") is always passed in from the caller rather than read via
// redis TIME: it keeps the scripts deterministic under test (fake clocks,
// miniredis FastForward) and pins expiry decisions to one clock per call.
//
// Session keys are derived inside create/revoke-user scripts ("sess:" .. id),
// which is fine on a single Redis but would break cluster key hashing.
// ponytail: single-node Redis assumed; hash-tag the keys if cluster ever matters.

import "github.com/redis/go-redis/v9"

// createScript enforces the per-user concurrent session cap and writes the
// new session in one atomic step.
//
//	KEYS[1] = user index ZSET
//	ARGV    = now_ms, idle_ttl_ms, deadline_ms, max, policy, id, uid, realm, ip, ua
//
// Returns the array of evicted session IDs (possibly empty), or the string
// "LIMIT" when policy=reject and the user is at the cap.
var createScript = redis.NewScript(`
local now = tonumber(ARGV[1])
-- Don't COUNT a member that is not a live session, by the same test
-- touchScript, rotateScript and List apply: past its deadline (clock skew,
-- restored snapshot) or missing a defining field is dead, and counting one
-- would hold a cap slot List refuses to show and revoke-by-id cannot be aimed
-- at. But only UNLINK what Redis already collected. "now" is this node's
-- unvalidated clock and nothing here is broadcast, so a fast node must not
-- touch a record still live elsewhere: deleting it kills a live session
-- fleet-wide, and unlinking alone is worse — it keeps validating but drops out
-- of RevokeUser's reach. touchScript deletes it, on the node serving it.
-- Price: a node skewed past a session's deadline neither counts nor collects
-- it, so the cap is advisory under that much skew — same unvalidated clock,
-- same direction as RevokeUser's count.
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
local live = {}
for _, m in ipairs(members) do
  local h = redis.call('HMGET', 'sess:' .. m, 'deadline_ms', 'realm', 'uid', 'created_ms')
  local dl = tonumber(h[1])
  if h[2] == '' then h[2] = false end -- empty is missing; see touchScript
  if h[3] == '' then h[3] = false end
  if dl and h[2] and h[3] and tonumber(h[4]) and now < dl then
    live[#live + 1] = m
  elseif redis.call('EXISTS', 'sess:' .. m) == 0 then
    redis.call('ZREM', KEYS[1], m)
  end
end

local max = tonumber(ARGV[4])
local evicted = {}
if #live >= max then
  if ARGV[5] == 'reject' then
    return 'LIMIT'
  end
  -- evict-oldest: ZRANGE is score-ascending, so live[] is oldest-first.
  local need = #live - max + 1
  for i = 1, need do
    redis.call('DEL', 'sess:' .. live[i])
    redis.call('ZREM', KEYS[1], live[i])
    evicted[#evicted + 1] = live[i]
  end
end

local deadline = tonumber(ARGV[3])
local key = 'sess:' .. ARGV[6]
redis.call('HSET', key,
  'uid', ARGV[7], 'realm', ARGV[8], 'ip', ARGV[9], 'ua', ARGV[10],
  'created_ms', ARGV[1], 'seen_ms', ARGV[1], 'deadline_ms', ARGV[3])

-- Sliding idle TTL, clamped so the key can never outlive its absolute deadline.
local ttl = tonumber(ARGV[2])
if deadline - now < ttl then ttl = deadline - now end
redis.call('PEXPIRE', key, ttl)

-- Index the session. The index must outlive every session it holds, so only
-- ever extend its TTL — never shorten it. A node configured with a smaller
-- AbsoluteTTL (rolling deploy, security tightening) would otherwise expire the
-- index out from under a longer-lived sibling, making that session invisible
-- to revoke-all, List and the cap. PTTL is -1 (persistent, i.e. the first ZADD
-- above) or -2 (missing); both compare below any positive want, so the TTL is
-- still established on a fresh key.
redis.call('ZADD', KEYS[1], now, ARGV[6])
local want = deadline - now
if redis.call('PTTL', KEYS[1]) < want then redis.call('PEXPIRE', KEYS[1], want) end
return evicted
`)

// touchScript validates and renews a session in one atomic step.
//
//	KEYS[1] = session hash
//	ARGV    = now_ms, idle_ttl_ms, id
//
// Returns the full session hash (flat field/value array) on success, or an
// empty array if the session is missing, past its absolute deadline, or
// corrupt. The deadline re-check matters: the key TTL is clamped at write
// time, but only this check protects against a node whose clock ran ahead when
// it last touched, or a Redis restore with stale TTLs.
var touchScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local now = tonumber(ARGV[1])
local deadline = tonumber(redis.call('HGET', KEYS[1], 'deadline_ms'))
local realm = redis.call('HGET', KEYS[1], 'realm')
local uid = redis.call('HGET', KEYS[1], 'uid')
local created = redis.call('HGET', KEYS[1], 'created_ms')
-- HGET yields false for a missing field but '' for an empty one, and '' is
-- truthy in Lua: without this an empty realm passes every guard below and then
-- names the index 'usersess::uid:sessions', which checkNames can never spell,
-- so RevokeUser can never target it. Empty is missing in every script that
-- makes a liveness decision. revokeScript is deliberately exempt: it DELs
-- first regardless, so its ZREM of a wrongly-named index is a harmless no-op
-- that create's prune collects on the next write.
if realm == '' then realm = false end
if uid == '' then uid = false end
-- One liveness test for every way a record stops being a session: past its
-- deadline, or missing/unparsable a defining field (partial restore, operator
-- surgery — a missing field arrives as false). Fail closed and delete: a record
-- no sibling script can revoke, rotate or count must never authenticate. Same
-- policy in create/rotate/revoke/List; there is no tolerant path.
if not deadline or not realm or not uid or not tonumber(created) or now >= deadline then
  redis.call('DEL', KEYS[1])
  return {}
end
redis.call('HSET', KEYS[1], 'seen_ms', ARGV[1])
local ttl = tonumber(ARGV[2])
if deadline - now < ttl then ttl = deadline - now end
redis.call('PEXPIRE', KEYS[1], ttl)

-- Hold the user index open for at least as long as this session. The index
-- TTL is frozen at create time, but the PEXPIRE above restretches the session
-- key from the *caller's* clock: a node whose clock trails Redis at touch time
-- relative to create time (backward NTP step, drifting VM) pushes the key past
-- the index, and the orphaned session then survives revoke-all and is invisible
-- to List and the cap. Same extend-only rule as createScript. The ZADD NX also
-- re-indexes a session already orphaned that way, which PEXPIRE alone cannot —
-- it is a no-op on a missing key. Score is created_ms so eviction order stays
-- by session age. ponytail: ~3 extra ops per cache miss, i.e. one per CacheTTL
-- per token; move to a background reaper if that ever shows up in a profile.
local userkey = 'usersess:' .. realm .. ':' .. uid .. ':sessions'
redis.call('ZADD', userkey, 'NX', tonumber(created), ARGV[3])
local want = deadline - now
if redis.call('PTTL', userkey) < want then redis.call('PEXPIRE', userkey, want) end
return redis.call('HGETALL', KEYS[1])
`)

// rotateScript implements rotate-on-privilege-change: the old session ID dies
// and a new one takes over its identity in the same atomic step, so there is
// no window where both (fixation) or neither (dropped session) are valid.
// created_ms and deadline_ms carry over — rotation never extends a lifetime.
//
//	KEYS[1] = old session hash, KEYS[2] = new session hash
//	ARGV    = now_ms, idle_ttl_ms, old_id, new_id, ip, ua
//
// Returns the new session hash (flat array), or an empty array if the old
// session is missing, expired or corrupt.
var rotateScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local now = tonumber(ARGV[1])
local deadline = tonumber(redis.call('HGET', KEYS[1], 'deadline_ms'))
local uid = redis.call('HGET', KEYS[1], 'uid')
local realm = redis.call('HGET', KEYS[1], 'realm')
local created = redis.call('HGET', KEYS[1], 'created_ms')
-- Empty is missing; see touchScript. Before the DEL, so the refusal below is
-- reached instead of a half-rotated session Go rejects afterwards.
if realm == '' then realm = false end
if uid == '' then uid = false end
redis.call('DEL', KEYS[1])
-- The old ID dies either way, so unlink it either way — a refused rotation must
-- not leave a member pointing at nothing for RevokeUser to count.
local userkey = realm and uid and ('usersess:' .. realm .. ':' .. uid .. ':sessions')
if userkey then redis.call('ZREM', userkey, ARGV[3]) end
-- Same liveness test as touchScript: a dead or corrupt record must not be
-- reborn under a fresh ID.
if not deadline or not userkey or not tonumber(created) or now >= deadline then return {} end

redis.call('HSET', KEYS[2],
  'uid', uid, 'realm', realm, 'ip', ARGV[5], 'ua', ARGV[6],
  'created_ms', created, 'seen_ms', ARGV[1], 'deadline_ms', tostring(deadline))
local ttl = tonumber(ARGV[2])
if deadline - now < ttl then ttl = deadline - now end
redis.call('PEXPIRE', KEYS[2], ttl)
-- Keep the original creation time as the score so eviction order is by
-- session age, not rotation time.
redis.call('ZADD', userkey, tonumber(created), ARGV[4])
-- Rotating a user's only session empties the ZSET, which Redis deletes along
-- with its TTL; the ZADD above then recreates it with no expiry at all. Same
-- extend-only rule as createScript: reinstate the TTL, never shorten a
-- longer-lived sibling's.
local want = deadline - now
if redis.call('PTTL', userkey) < want then redis.call('PEXPIRE', userkey, want) end
return redis.call('HGETALL', KEYS[2])
`)

// revokeScript deletes one session and its index entry atomically. The user
// key is derived from the record because callers may only know the ID.
//
//	KEYS[1] = session hash
//	ARGV    = id
// Deleting first is deliberate: revocation is the last resort and must never be
// blocked by a record too damaged to name its own index. DEL returns 0 on a
// missing key, which is exactly the idempotent contract callers rely on.
var revokeScript = redis.NewScript(`
local uid = redis.call('HGET', KEYS[1], 'uid')
local realm = redis.call('HGET', KEYS[1], 'realm')
local n = redis.call('DEL', KEYS[1])
if uid and realm then
  redis.call('ZREM', 'usersess:' .. realm .. ':' .. uid .. ':sessions', ARGV[1])
end
return n
`)

// revokeUserScript deletes every session of a user atomically (global
// logout), so a concurrent create cannot slip a session between the read of
// the index and the deletes.
//
//	KEYS[1] = user index ZSET
//
// Returns the revoked session IDs.
var revokeUserScript = redis.NewScript(`
local members = redis.call('ZRANGE', KEYS[1], 0, -1)
for _, m in ipairs(members) do
  redis.call('DEL', 'sess:' .. m)
end
redis.call('DEL', KEYS[1])
return members
`)
