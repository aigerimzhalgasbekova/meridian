---
title: Lessons learned
chapter: 10
summary: An honest synthesis — the bugs that taught something, what building this way was like, and what would be different next time.
---

A portfolio that only reports successes is a brochure. This chapter is the retrospective: the bugs worth remembering, the process observations, and the things a second pass would do differently.

## Three bugs worth their tuition

**The escaping bug (idp).** Covered in detail in [chapter 3](/guide/the-authorization-server/): the browser-flow test harness scraped `return_to` and CSRF values out of rendered HTML with a regex and posted them back verbatim — but `html/template` had (correctly) entity-escaped the attribute values, so the tests were submitting `&amp;`-escaped query strings no browser would ever send. The server was right; the template was right; the test spoke a protocol nobody speaks. The fix was `html.UnescapeString` in the harness with a comment explaining that a browser HTML-decodes attribute values before submitting them. **Lesson:** a test harness below the level of a real browser *is* a browser emulator, and it must emulate correctly — decoding, cookies, redirects. Both the template and the regex look right in isolation; the bug lives in the seam.

**The fake-clock bug (portal).** The job-queue tests drive time with a fake clock to test backoff and dead-lettering without sleeping. The in-memory queue initially consulted the ambient clock (`new Date()`) inside its claim logic while the tests advanced the fake one — so the queue and the test disagreed about what time it was, and backoff behavior couldn't be tested deterministically. The fix is visible in the final interface: `claim(now)` and `fail(id, error, now)` take the clock **as an argument**; nothing inside the queue reads time ambiently. **Lesson:** a fake clock only works if there is exactly one clock. Any component that reads ambient time is a hole in the determinism, and the type signature is the right place to enforce it — sessiond independently applies the same rule by passing `now` into every Lua script rather than calling Redis `TIME`.

**The device-flow `return_to` fix (idp).** idp's login form carries a `return_to` so it can bounce you back to where you were — and an unconstrained `return_to` is an open redirect, so validation confines it to known same-realm paths. Originally that meant `/authorize` paths, which broke when the device flow (RFC 8628) needed a login step from its verification page. The tempting fix was to point `return_to` at a synthetic authorize URL to sneak past the validator; the comment in [`device.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/idp/internal/server/device.go) records that this was considered and rejected — instead the device page does its own login redirect and the validator explicitly allows same-realm authorize *and* device paths. **Lesson:** when a security control blocks a legitimate flow, the answer is to extend the control's model of "legitimate", never to teach the flow to impersonate something the control already trusts. Workarounds that defeat your own validator are self-inflicted vulnerabilities with extra steps.

## What building it this way was like

This platform was built autonomously by AI agents working from a design document and a task list, with structured review passes — an unusual enough construction method that the observations belong in the record.

**The design doc earned its keep daily.** Decisions made once, in writing, before code — the eight-project decomposition, the stdlib-first rule, the no-Docker testing constraint — stayed made. Nearly every "should this be X or Y?" moment during the build resolved by consulting the doc rather than re-litigating.

**ADRs written at decision time are a different artifact than ADRs written after.** The ones in this repo argue with real alternatives (sessiond's ADR 0002 genuinely weighs `WATCH`/`MULTI` and Redlock; sentinel's ADR 0001 rejects the sliding log for a reason that's really a threat model) because the alternatives were live options minutes before. Retrospective ADRs tend to be justifications.

**Review passes with different lenses found different bugs.** The escaping bug fell out of asking "does this test actually prove what it claims?" — a completeness question, not a security one. The lockout anti-DoS design came from the security lens asking "how do I weaponize this control?". No single pass would have caught both.

**Constraints improved the architecture.** No Docker on the dev machine forced every storage dependency behind a narrow interface with a faithful fake — which is why the suites run in seconds, why miniredis executes the production Lua scripts unmodified, and why the deployment seams in [chapter 9](/guide/running-it/) exist at all. The constraint was an annoyance for a day and a design principle thereafter.

## What would be different next time

- **Integration across services is thinner than within them.** Each service is thoroughly tested in isolation with its neighbors faked; a compose-based cross-service smoke suite (idp actually calling keysmith actually rotating keys under load) is designed but blocked with the platform project. Next time, a minimal two-service integration harness would land earlier.
- **The `platform` project should not be last.** Terraform written after seven services means seven services' worth of environment variables to reverse-engineer into task definitions. Writing skeleton infrastructure alongside service #2 would have kept the deployment honest continuously instead of at the end.
- **Shared test vocabulary emerged too late.** keysmith, sessiond, and portal each independently invented fake-clock plumbing. A tiny shared testing note ("clocks are always arguments") existed implicitly by project three; writing it down at project one would have saved the portal bug above.
- **Some duplication was the right call, and it's worth saying so.** bridge reuses keysmith's `jose`, but idp and console deliberately do not share storage helpers or middleware — the no-shared-structs rule kept every repo independently reviewable, at the cost of some repeated boilerplate. Next time: same call.

## The honest bottom line

Seven services, 398 Go tests under `-race` plus 50 TypeScript and 11 Python tests, every suite green on a machine with no Docker daemon, every security claim traceable to an ADR, a threat model, and a named test. Not deployed yet — that's an AWS account away, and [chapter 9](/guide/running-it/) is precise about the gap. The thing this portfolio is meant to prove isn't that the author can make software exist; it's that the software can survive the questions a careful reviewer asks. The ADRs, the threat models, and this chapter are standing invitations to ask them.
