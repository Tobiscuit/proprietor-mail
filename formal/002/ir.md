# Spec 002 — protocol IR for formal verification

**Status:** written 2026-10-19, before any Tamarin run. Every proof target in
§7 carries the verdict we expected *before* running the model; `README.md`
holds what Tamarin then said. Method: the "confidence-guided protocol IR" of
arXiv 2609.37396 — a plain intermediate representation first, reviewed for
*meaning* by a person, then the model generated from it
(`device.spthy`), then the tool's verdicts. The IR carries the paper's
fields: participants, state, value provenance, cryptographic operations,
message flows, compromise assumptions, proof targets.

**What to look at.** Every item has a confidence mark that says how far it is
a straight reading of the contract and how far a modelling choice:

- **HIGH** — a direct transcription of `contracts/device-v1.md` or the spec.
- **MEDIUM** — a modelling choice; the reviewer should confirm it means what
  the system means. These are the items worth a careful read.
- **LOW** — an abstraction that drops something on purpose; what is dropped
  is named, and §8 says why it does not change the verdicts.

Contract sections are cited as `A4`, `B7`, `K2′` (from `device-v1.md`),
`M18` (from `domain-model.md`), `D25` (from `spec.md`). Example values only:
a mailbox is `m`, keys are `K0, K1, …`, devices `D1, D2, …`.

## 1. Participants

| # | Role | What it is in the system | In the model | Confidence |
|---|---|---|---|---|
| P1 | **Stateless browser** ("shared computer" page) | A browser that unlocks with a factor and keeps nothing (spec R4, D31). | A page that holds the active key in memory after a factor unlock. Any number may exist at once. | HIGH |
| P2 | **Kept device** | One browser profile with two P-256 keys in IndexedDB and the id of the key it last accepted (K5). | A record `(device id, last accepted key)` plus the two private keys, and a page holding the active key while unlocked. Any number. | HIGH |
| P3 | **Factor secret** | The recovery key, or a security key's PRF output for this mailbox (A2). Used only when a person types or touches it. | One factor per mailbox, held by the owner, usable from any browser at any time. | MEDIUM — one factor stands for all; the model does not distinguish passkey from recovery key, and the owner is always willing to use it. Confirm that nothing in §7 depends on having two factors. |
| P4a | **Mail as a store** (attacker-controlled) | The key ring the browser reads from `mailbox()`: keys, successor seals, wraps, factor keys, tags, devices, seals (B4). | **The attacker.** Everything a browser reads comes from the attacker; everything a browser sends is seen by the attacker. The dashboard relay is the same attacker (it is the network). | HIGH — as instructed. |
| P4b | **Mail as a verifier** (honest) | The checks the Worker code enforces on data it made itself: a challenge is used once (M16), an answer is compared by hash (B6), a device signature is verified (A7), a rotation is applied only with a live session and a spent factor proof (B3, B7), and inbound mail is sealed to the key its own active pointer names. | Honest rules with their own records: the active-key pointer, the **factor public keys registered at enrollment**, challenges and sessions. A session challenge is sealed to the pointer's key; a factor challenge to the registered factor key. Every *request* (an answer, a rotation, a device signature and the public key to check it with) arrives from the attacker. | MEDIUM — the split is: *the view the browser reads is hostile, the records Mail's own checks rely on are honest.* Without the second half, D25 would be void in the model (an attacker who can rewrite the stored factor key answers its own factor challenges), and nothing about proofs could be learned. In the system the factor keys are written once (enrollment, or the upgrade) and changed only with a factor proof. Confirm this is the question you want answered. |
| P5 | **Removed device as a compromise event** | A lost or stolen device, locked or unlocked (spec §4 rows 1–3). | At any moment the attacker may take everything a kept device stored or ever held in a page: its two device keys and every mailbox key it accepted or walked through. | HIGH |
| P6 | **Honest sealer** (Mail's inbound path) | `Mailbox.deliver` seals each arriving message to `activeKey()`. | Two versions. **H1** seals to the key the honest pointer names. **H2** seals to a key the store hands it (this is finding A of the review: the client opens any key it holds without checking the key's `retiredAt`). | HIGH |

## 2. State

| # | Who | State | Meaning | Confidence |
|---|---|---|---|---|
| S1 | owner | `Factor(m, fid, fs)` | the factor secret `fs` of factor `fid`, forever | HIGH |
| S2 | Mail (verifier) | `MailActive(m, pk)` | the active-key pointer; set at enrollment, moved only by an applied rotation | HIGH |
| S3 | Mail (verifier) | `MailSessionChallenge(chid, pk, ans, nonce)`, `MailFactorChallenge(chid, fid, pkF, ans)` | a live challenge; consumed by the one call that answers it (M16) | HIGH |
| S4 | Mail (verifier) | `MailSession(tok, pk, who)` | an open session: bearer token `tok`, opened with a proof of key `pk`, by device `who` or by no device | MEDIUM — sessions never expire in the model (60 minutes in B6). Expiry only removes attacker options. |
| S5 | P1 | `PageS(m, sk)` | a stateless page unlocked with active private key `sk` | HIGH |
| S6 | P2 | `PageD(m, did, sk)` | a kept device's page unlocked with `sk` | HIGH |
| S7 | P2 | `Kept(m, did, lastpk)` + `DevKeys(m, did, dsk, dss)` | the record (K5): last accepted key, the unlock key `dsk`, the signing key `dss` | HIGH |
| S8 | P2 | `Held(m, did, sk)` | device `did` had mailbox key `sk` in a page at some time (G40: a session holds every key the chain reaches) | HIGH |
| S9 | P1/P2 | `WalkS(m, anchor, skact, skcur)`, `WalkD(m, did, anchor, skact, skcur)` | a chain walk in progress (K2′): trying to accept `skact`, currently at `skcur`, must reach `anchor` | HIGH |
| S10 | P1/P2 | `Rotating(m, skold, sknew, didrm)` | a rotation this page made: it may seal `sknew` to any recipient whose tag under `skold` verifies, except the removed device `didrm` (B7, K3) | HIGH |
| S11 | P1/P2 | `PreparingS/D(…)` | a rotation prepared (new key drawn) and not yet committed | MEDIUM — exists so the bound-proof variant can name the request before the factor challenge is sealed. |

One thing the model keeps that the code does not: a kept device updates its
`lastKeyId` **only if it is still the value the walk started from**
(compare-and-swap, S7 in rule A2). The code overwrites unconditionally
(`resume.ts` step 5, `session.ts` unlockWithFactor). See §8, item 9.

## 3. Values and who learns them

| Value | Made by | Learned by | Never by | Contract | Confidence |
|---|---|---|---|---|---|
| `m`, `fid`, `did`, `chid` | the maker named in A1 | everyone | — | A1 | HIGH |
| `K_i` (mailbox private key) | the enrolling browser (`K0`), a rotating browser (`K_{i+1}`) | any recipient a key holder seals it to; the chain holds `K_i` for every holder of `K_{i+1}` | Mail | A4, M3 | HIGH |
| `fs` (factor secret), `skF = fkey(fs, fid)` | the owner; derived in the browser while the factor is in use | the owner's browser only | Mail, the attacker | A2 | HIGH |
| `pkF` | derived from `skF` | everyone | — | A2 | HIGH |
| `kek(fs, fid)` | derived from `fs` | the browser using the factor | Mail | envelope v1 | HIGH |
| `dsk`, `dss` (device keys) | the device | the device; the attacker on compromise | Mail | A3 | HIGH |
| `bindkey(K)` | any holder of `K` | holders of `K` | Mail, unless `K` leaked | A5 | **LOW** — stands for the self-Diffie-Hellman key; "only a holder of `K` can make or check a tag" is *assumed*, not derived. The Square-DH argument is a separate, later item. |
| `ans` (challenge answer) | Mail (verifier) | the holder of the key it was sealed to; then the attacker, because the answer is relayed in the clear | — | A6, A8 | HIGH |
| `nonce`, `tok` | Mail | everyone (the token passes through the dashboard) | — | A7, A8 | HIGH — public the moment they exist, so the model does not give them names: the device signs the challenge id, and a session is simply open (see "choices made for the prover") |
| `dek` (message key) | the sealer | holders of the key it was sealed to | Mail | envelope v1 | HIGH |

## 4. Cryptographic operations and their symbolic form

| Operation | In the system | In the model | Confidence |
|---|---|---|---|
| HPKE base-mode seal to `pk`, with `info` and `aad` | A4, A6, envelope v1 | `aenc(<tag, ids…, payload>, pk)`. The tag and the ids inside the plaintext stand for `info` and `aad`: a ciphertext made for one purpose does not open as another (K4). | HIGH — this is what HPKE's `info` does. The run `ORACLE_MUTANT` removes the separation to show the verdict depends on it. |
| Envelope v1 wrap | `AES-GCM(kek, pkcs8(K))` | `senc(K, kek(fs, fid))` | HIGH |
| Key seal to a device or factor | A4 | `aenc(<'keyseal', K, kind>, pkRecipient)`; the mailbox and recipient ids of A4's `info` are left out because the recipient's key already fixes them (a seal opens only for its recipient) | HIGH |
| Successor seal | A4 | `aenc(<'succ', K_old>, pk(K_new))`: the old private key, sealed to the new public key | HIGH |
| Binding tag | A5 | `mac(<kind, m, id, public keys…>, bindkey(K))` | LOW (see §3) |
| Factor key | A2 DeriveKeyPair | `fkey(fs, 'f1')`, public `pk(fkey(fs, 'f1'))` (one factor, so its id is a constant) | HIGH |
| Session challenge | A6 | `aenc(<'challenge', 'session', chid, ans>, pk)` | HIGH |
| Factor challenge | A6 | `aenc(<'challenge', 'factor', chid, ans>, pkF)`; with `BOUND_PROOFS`: `…, chid, bind, ans` where `bind = h(request)` | HIGH / the bound form is a proposed change, not the contract |
| Device proof | A7 | `sign(<'proof', did, chid>, dss)`: A7's nonce is redundant once the challenge id is fresh | HIGH |
| Message-key envelope | envelope v1 | `aenc(<'msgkey', dek>, pk)` | HIGH |
| `keyId` | first 16 bytes of SHA-256(pk) | the public key itself | HIGH — a hash is a bijection in the symbolic model |
| Key commitment of AES-GCM, clamping, PKCS #8 lengths | A4, envelope v1 | not modelled | LOW — bytes-level; outside a symbolic model's reach |

**Choices made for the prover, not for the protocol** (MEDIUM — confirm
they lose nothing you care about; README.md says what each one cost before
it was made):

- *A mailbox private key is the term `mkey(~x)`*, a fresh name under a free
  constructor, never a bare fresh name. Tamarin cannot tell one fresh name
  from another by sort, so with bare names it had to consider that a page
  might hold the factor secret as its key, and could refute that only by a
  chain argument it never finished (its depth-bounded proof tree for
  `factor_secret` sourced "the attacker knows the factor secret" from a
  device seal). The attacker can still build `mkey(y)` for any `y` it knows,
  so attacker-made keys, the fork and the relay hijack stay expressible.
  (Tamarin's "message derivation" lint reports every rule that matches
  `mkey(~x)`; the runs switch that one lint off, README.md says where.)
- *Received keys, answers and ids are matched as fresh names.* Where a rule
  reads a mailbox key out of a wrap, a seal or a successor seal, a challenge
  answer out of a challenge, or a factor or device id out of a record, the
  model requires a fresh name (`~x`) there. Every honest value in those
  positions is a fresh name, and the attacker can mint fresh names of its own
  and use them in every attack described in §7 (its own key in the fork and
  the relay hijack, its own device id in the planted record). What is
  excluded is an attacker sending a *composite* term as a key, which no rule
  could use as one anyway. Without this, Tamarin's sources analysis does not
  terminate (ir.md was written before that was known; README.md records it).
- *Signatures are verified, not pattern-matched* (M2): Mail receives a
  signature and a public key and checks `verify(sig, message, pk) = true`,
  which is what the Worker does (A7); the digest in the bound-proof variant is
  matched as `h(request)` on purpose.
- *A page is persistent, and records carry an id.* An unlocked page is a fact
  that is never consumed: the page holds every key it ever accepted (which is
  G40), and may still act with an older one — Mail's pointer decides what
  counts, so this only gives the attacker more. The device record, the chain
  walks and a prepared rotation carry a fresh id in first position. Both let
  Tamarin treat these facts as *injective*, without which the existence
  searches for the sanity lemmas did not terminate.
- *Honest messages travel on named channels, and the attacker may write to
  every channel.* An answer, a device's signed answer, a factor answer, a
  rotation request, a device record and a factor record are each a fact the
  honest sender puts down **and** publishes; six injection rules (`Z…`) let
  the attacker put any content it can compute on the same channel. That is
  the Dolev-Yao power of a plain `In()`, arranged so that the honest source
  of a message is examined before the attacker's.
- *An honest answer is routed, not learned.* A challenge answer (and a
  device's signed answer) goes on its channel, which the attacker controls
  completely: it can hold it back, replay it, or pair it with a request of
  its own, which is everything the relay can do with the bytes in the
  system. The model does not also add the bytes to the attacker's knowledge:
  knowing them buys nothing beyond routing (an answer is tied to its
  challenge), and modelling it let the prover re-derive the challenge from
  the answer it had just learned, in an endless circle. The attacker still
  learns an answer the honest way whenever it holds the key the challenge
  was sealed to.
- *Public-the-moment-they-exist and symbolically redundant values are not
  fresh names.* The challenge nonce (the challenge id is already fresh; the
  device signs the id), the session token (a bearer secret the attacker
  always holds, so a session is simply "open"), the factor id (one factor:
  `'f1'`), and the mailbox and recipient ids inside encrypted payloads (the
  recipient's key already binds them; the tags still cover them). Each fresh
  name in an honest output is one more case for every "the attacker knows
  some fresh name" goal; two hundred of them made every search stall.
- *The secrecy lemmas come first and are reused.* `mailbox_key_secret`,
  `factor_secret` and `dek_secret_honest_key` are proven first (by
  induction) and marked for reuse, so every later proof may assume them. A
  successor seal lets anyone who holds `K_{i+1}` open `K_i`; without the
  reused lemma the prover chases "does the attacker know `K_i`?" through an
  unbounded chain of rotations. The lemmas say what they said before; only
  their place and annotation changed.
- *Rules are named in the order Tamarin should try them as sources* (`A00`
  for enrollment through `A28` for compromise, `Z` for injection), because
  the prover tries the cases of a goal in alphabetical order of the rules
  that could have produced it; base cases before loops, honest before
  attacker. `oracle.py` additionally orders the goals within a proof state:
  protocol facts first, knowledge of fresh names last.

## 5. Message flows

Each step: who acts, what it needs, what it does, what the attacker learns.
"Reads from the store" means the value arrives from the attacker.

| Step | Who | Needs | Does | Attacker learns | Contract | Confidence |
|---|---|---|---|---|---|---|
| **E1 Enroll** | a new stateless page | nothing | makes `m`, `K0`, factor `fid` with secret `fs`; publishes `pk(K0)`, the wrap `senc(K0, kek)`, `pkF`, and the factor's tag under `bindkey(K0)`; Mail's pointer starts at `pk(K0)` and Mail registers `pkF` as the factor's key; the page is unlocked with `K0` | all of it except `K0`, `fs` | B5, envelope v1 | MEDIUM — the enrollment request is assumed to reach Mail unmodified (both the key and the factor key). A relay that swaps either at enrollment is a 001 concern (G7 and K9 catch it at the next unlock) and is out of scope here. |
| **U1 Unlock, stateless** | P1 with the factor | the wrap from the store; for U1b also a seal of the active key to `pkF` | opens the wrap → `K0` is the **anchor**; the active key is `K0` (U1a) or the key inside the factor seal (U1b); starts a walk from the active key to the anchor | which factor was used | K2′ (a)/(b) | HIGH |
| **U2 Unlock, kept device after a lock** | P2 with the factor | as U1, plus its record | as U1, but the anchor is `lastpk` from the record | as U1 | K2′ | MEDIUM — K2′ names two anchors (the wrap's key and `lastpk`); the model uses `lastpk`, which is the later of the two, so it is the stricter check. |
| **W1 Walk step** | P1/P2 mid-walk | a successor seal from the store | opens `aenc(<'succ', m, K_prev, pk(K_cur)>, pk(K_cur))` with `K_cur`, now at `K_prev`; a device remembers it held `K_prev` | nothing | K2′, G40 | HIGH |
| **A1/A2 Accept** | P1/P2 | the walk is at the anchor | the active key is accepted; the page is unlocked with it; a device writes `lastpk := the accepted key` only if the record still holds the walk's anchor | nothing | K2′, K5 | MEDIUM — the compare-and-swap (§2) |
| **R1 Resume** | P2 | its record, its unlock key, a seal of the active key to its unlock key from the store | opens the seal, starts a walk from that key to `lastpk` | nothing | F2, K2′ | HIGH |
| **K1 Keep this device** | P1, after a factor | the unlocked page | makes `did`, `dsk`, `dss`; publishes their public halves, the active key sealed to `pk(dsk)`, and the device's tag under `bindkey(K_active)`; the page becomes the device's page; record `lastpk := pk(K_active)` | the public record, the seal, the tag | B7, K5 | MEDIUM — Mail's own check of the registration (a factor proof, D25) is not modelled: the store is the attacker, so a record is simply there or not. |
| **C1 Session challenge** | Mail (verifier) | its own pointer's key | draws `chid`, `ans`; publishes `chid` and `aenc(<'challenge','session',chid,ans>, pointer key)`; remembers the challenge | all of it except `ans` | A6, B6 | HIGH |
| **C2 Factor challenge** | Mail (verifier) | the factor public key it registered at enrollment (with `BOUND_PROOFS`: also a request digest `bind` from the network) | as C1, sealed to `pkF`, tagged `'factor'` | as C1 | A6, B6 | HIGH — see P4b for why the registered key, not the view's |
| **P1/P2 Session proof** | P1 / P2 | the unlocked page; a challenge sealed to a key the page holds | answers `ans`; a device adds `sign(<'proof', did, chid>, dss)` | `ans`, the signature | A6, A7 | HIGH |
| **P3 Factor proof** | the owner | the factor; a challenge sealed to `pkF` | answers `ans` | `ans` | A6, D25 | MEDIUM — the owner answers *any* factor challenge at any time (the code answers only within two minutes of a factor use, K1′). More willing than the code: whatever holds here holds there. With `BOUND_PROOFS` this step disappears: a factor challenge is answered only inside T2, and only when its digest is the digest of the request the page is about to send. |
| **M1/M2 Open session** | Mail (verifier) | a live challenge and its answer; for a device, the signature and the device's public signing key read from the store | consumes the challenge; opens a session (the bearer token is public knowledge, so it is not named) | nothing new | B6 | HIGH |
| **M3 Apply rotation** | Mail (verifier) | a live factor challenge and its answer, a session for the current active key, and a request `(pk_old, pk_new)` from the network | consumes the proof; if `pk_old` is the pointer, moves the pointer to `pk_new` | nothing new | B3, B7 step 1 | MEDIUM — Mail checks ids and lengths of the seals and tags in a rotation, never their content (it cannot: B7). So the request Mail accepts is just `(pk_old, pk_new)`. With `BOUND_PROOFS`, the challenge's digest must equal `h(request)`. |
| **T1 Prepare rotation** | P1/P2 unlocked | a device id to remove, from the store | draws `K_new`; publishes `h(<'rotate', m, pk(K_old), pk(K_new)>)` | the digest | B7, K8 | MEDIUM — the digest is only used by the bound variant. |
| **T2 Commit rotation** | P1/P2 with the factor | the prepared rotation; with `BOUND_PROOFS`: the factor challenge whose digest matches | publishes `pk(K_new)` and the successor seal; the page moves to `K_new`; a device's record moves to `pk(K_new)`; the page may now seal `K_new` (T3/T4); the removed device is `didrm` | `pk(K_new)`, the successor seal (with `BOUND_PROOFS` also `chid`, `ans`) | B7, M18, K8 | HIGH |
| **T3 Seal to a device** | the rotating page | a device record `(did, pkS, pkU, tag)` from the store whose `tag` verifies under `bindkey(K_old)`, and `did ≠ didrm` | publishes `K_new` sealed to `pkU`, and the record's tag under `bindkey(K_new)` | the seal, the tag | B7 steps 2–3, K3 | HIGH |
| **T4 Seal to a factor** | the rotating page | a factor record `(fid, pkF, tag)` from the store whose tag verifies under `bindkey(K_old)` | publishes `K_new` sealed to `pkF`, and the tag under `bindkey(K_new)` | the seal, the tag | B7, K3, M5′ | HIGH |
| **H1 Seal inbound mail (honest pointer)** | Mail | its pointer `pk` | draws `dek`; publishes `aenc(<'msgkey', m, dek>, pk)` | the envelope | envelope v1, B7 step 6 | HIGH |
| **H2 Seal inbound mail (store-chosen key)** | Mail | a key from the store | as H1 with that key | the envelope | — (finding A) | HIGH |
| **X1/X2 Compromise** | the attacker | a kept device | takes `dsk`, `dss`, and every mailbox key the device ever held | those keys | spec §4 rows 1–3 | HIGH |

Not modelled: lock timers (K6), the one-time upgrade of a legacy mailbox
(B5), adding or replacing factors (B7), drafts and reading old mail,
labels, housekeeping. §8 says why each is safe to leave out.

## 6. Attacker and compromise assumptions

- The attacker is the network between browser and Mail (the dashboard relay)
  **and** Mail's storage. It sees every message, can replay, reorder, drop,
  and fabricate anything it can compute. — HIGH (as instructed)
- Mail's *checks* are honest (P4b). — MEDIUM (see P4b)
- A kept device may be compromised at any time (X1, X2), before or after it
  is removed. Several proof targets restrict *when*. — HIGH
- Factor secrets never leak. Stateless pages never leak. — MEDIUM — a stolen
  "shared computer" page is covered by the kept-device case (a page is a
  weaker device), and a leaked recovery key is total loss by design (spec §4).
- Honest parties never misbehave; there is no "owner removes the wrong
  device" error. — HIGH

## 7. Proof targets, with the verdict expected before running

The names are the lemma names in `device.spthy`. "Expected" was written
before the first run. "Why" is the reasoning; where a target is expected to
fail, the trace we expect is described in plain words.

### (i) Post-removal secrecy of message keys

| Lemma | Says | Expected | Why |
|---|---|---|---|
| `post_removal_secrecy_compromise_after_removal` | If the owner's rotation that removed `D` was applied, and Mail (H1) then seals a message key to the new key, that message key stays secret — even if `D`, and any device removed by an earlier applied rotation, is compromised **after** its removal. | **hold** | `D` never receives a seal of the new key (T3 skips `didrm`), successor seals only run backwards, the factor's seal needs `skF`, and the tags `D`'s leaked key can forge are under a key no applied rotation starts from any more. |
| `post_removal_secrecy_compromise_before_removal` | As above, but `D` may be compromised **before** it is removed (a stolen, unlocked device). | **fail** | Found while writing this IR: with `K_old` in hand the thief computes `bindkey(K_old)` and (with the store's cooperation, since the store is the attacker) lists a **planted recipient with a genuine tag**. The owner's rotation seals the new key to it (T3): the planted recipient receives every later key. In the system this needs Mail to write a device record without a factor proof — i.e. a hostile or compromised Mail, or the relay redirecting an owner's unbound proof (finding C). K3 cannot tell a thief's tag from the owner's: both are made with the mailbox key. |
| `post_removal_secrecy_applied_rotation_no_compromise` | With **no** device compromised at all: after any rotation Mail applied, message keys sealed to the new key are secret. | **fail** (base) / **hold** (`BOUND_PROOFS`) | A factor proof is not bound to the request it authorises (B1/B3; finding C, stronger than reported): the relay keeps the owner's session token and relays the owner's factor answer with **its own** request `(pk_old, pk_attacker)`. Mail checks nothing about the seals, so the pointer moves to the attacker's key and inbound mail is sealed to it. The owner's browsers notice at the next unlock (no chain to the attacker's key), but the mail arriving in between is the attacker's. With the challenge bound to `h(request)`, the owner answers only for its own request. |
| `post_removal_secrecy_store_sealer` | If the sealer takes its key from the store (H2) — restricted to the mailbox's own honest keys — a message key sealed after `D` was removed is secret from a compromised `D`. | **fail** | Finding A: the store hands the sealer the retired key; `D` held it. The client opens any key it holds without looking at `retiredAt`. |

### (ii) Chain agreement and rollback

| Lemma | Says | Expected | Why |
|---|---|---|---|
| `chain_agreement_stateless_no_compromise` / `chain_agreement_kept_no_compromise` | With no compromise, a key a browser accepts as active was made by an honest browser of this mailbox. | **hold** | A successor seal holds the old private key, which only its holders have; a seal of the "new" key alone never passes the walk (K2′). |
| `chain_agreement_stateless_after_removed_compromise` | Even if every compromised device was removed (and compromised only after that), a key a stateless browser accepts was made honestly. | **fail** | Found while writing this IR: a leaked old key `K_i` lets the attacker **fork** the chain: it makes its own `K_att`, a successor seal `K_i → K_att` (it holds `K_i`), and a seal of `K_att` to the factor key. A recovery-key unlock is anchored at `K0` forever; the walk `K_att → K_i → … → K0` reaches it. The same fork takes any kept device whose `lastpk` is `K_i` or older. Devices already at `K_{i+1}` refuse it. In the system: a stolen device plus a hostile Mail reads mail that arrives on the fork; nothing stored under honest keys. |
| `kept_device_no_rollback` | A kept device never accepts the predecessor of a key it accepted before (one step), with every compromised device removed first. | **hold** | The anchor moves forward; a walk from `K_old` can never reach `K_new`, and nobody can make "`K_new` sealed to `K_old`" without `K_new`. |
| `stateless_rollback_possible` (exists-trace) | A stateless browser can accept `K_new` and later `K_old`, with no compromise (the trace shape is pinned like the sanity lemmas'). | **trace exists** (fails by design) | It has no memory (spec D31). The store shows an older ring to a fresh recovery-key unlock. |

### (iii) Recipient integrity

| Lemma | Says | Expected | Why |
|---|---|---|---|
| `recipient_integrity_compromise_after_removal` | A rotating browser seals an **applied** new key only to recipients an honest party registered, with every compromised device removed before its compromise. | **hold** | Tags under the leaked key authorise only rotations *from* that key, which Mail no longer applies. |
| `recipient_integrity_compromise_before_removal` | As above, but the removed device may have been compromised while it still held the active key. | **fail** | The planted recipient of (i), stated on its own. |

### (iv) Injective agreement

| Lemma | Says | Expected | Why |
|---|---|---|---|
| `factor_proof_agreement` | If Mail accepts a factor proof for an honest factor, the owner answered that exact challenge, earlier, and Mail accepts it once. | **hold** | Only `skF` opens the challenge; the challenge is consumed (M16). |
| `session_proof_agreement` | If Mail opens a session on a proof for an honest mailbox key (no compromise), an honest page answered that challenge, and once. | **hold** | as above with the mailbox key |
| `device_session_agreement` | If Mail opens a device session for an honestly registered, uncompromised device, that device signed that challenge, and once. | **hold** | the signature covers `chid` and the nonce (A7) |

### (v) No decryption oracle, and (vi) what Mail never learns

| Lemma | Says | Expected | Why |
|---|---|---|---|
| `mailbox_key_secret` | If the attacker knows an honest mailbox private key, some device of that mailbox was compromised. (A leaked key yields every older key through the public successor seals, so the statement cannot name the device that held *that* key.) | **hold** | keys travel only inside seals to honest recipients |
| `factor_secret` | Factor secrets and factor private keys are never known to the attacker. | **hold** | never sent |
| `dek_secret_honest_key` | A message key sealed to an honest mailbox key is known to the attacker only if some device of the mailbox was compromised. The challenge-answering rules are live in the same model, so this is also **(v)**: answering challenges leaks no message key. | **hold** (base) / **fail** (`ORACLE_MUTANT`) | HPKE `info` keeps challenges and envelopes apart (K4). The mutant seals message keys under the challenge `info`; then a page answers an envelope as if it were a challenge and the attacker reads the key. |

### Sanity (the model can run the honest flows)

`sanity_rotation_applied_and_sealed`, `sanity_kept_device_resumes_after_rotation`,
`sanity_stateless_unlocks_after_rotation`, `sanity_device_session` — each
**expects a trace**. A model where these find no trace proves nothing above.

## 8. What is left out, and why it does not change the verdicts

1. **Lock timers (K6), token and challenge expiry, the 20-challenge limit.** Time bounds only remove attacker options; a property that holds without them holds with them. Availability is not a target.
2. **The one-time upgrade (B5, D26)** of the one legacy mailbox. The model enrolls with factor keys from the start. Note: the upgrade takes a session and no factor proof, so the relay attack of (i) applies to it in the same way (a relay holding the session token can register its own factor keys); K9 then flags every factor at its next use.
3. **Adding a passkey, replacing the recovery key (B7).** They add recipients the way K1 does; nothing new for the targets.
4. **Several factors.** The chain and the seals treat every factor alike.
5. **Drafts, reading old mail.** Readers only; no secret leaves a page through them.
6. **Labels, lengths, `tagKeyId`.** Bytes-level checks; the symbolic tag covers the fields that matter (id and public keys).
7. **K3's strictness.** The code refuses a whole rotation while a flagged device other than the removed one exists; the model merely never seals to an unverifiable record. The model gives the attacker more, so a "hold" carries over.
8. **Square-DH and AES-GCM key commitment.** Outside a symbolic model; a two-page reduction is a separate item.
9. **The compare-and-swap of `lastKeyId`** (§2). The code overwrites it; two tabs shown different honest keys at the same time can move a device's anchor back by one step. Low impact (the earlier key is still honest); the fix is a conditional write. Reported, not modelled.
10. **Mail's device registration check (D25).** With the store as attacker, a record exists or not. The planted-recipient trace of (i)/(iii) is therefore stated against a hostile store; against an honest Mail it needs the relay plus an unbound proof (finding C).

## 9. What the operator should check in this IR

1. P4a/P4b: is "hostile storage, honest checks" the Mail you want examined?
2. P3: is one factor, always available, an acceptable stand-in for both factors?
3. E1: is "enrollment reaches Mail unmodified" an assumption you accept here (it is 001's problem)?
4. M3: is it true that Mail checks only `from` and the shapes of a rotation, never a seal's or a tag's content? (`src/mailbox/devices.ts`, `removeDevice`.)
5. P3: is "the owner answers any factor challenge" an over-approximation you accept (it only makes the attacker stronger)?
6. §7 (i) and (ii), the two "found while writing": do the plain-words traces describe something you consider inside the promise of spec §4, or outside it? The verdict table in `README.md` reports what Tamarin found; your call is whether the spec's threat model should say it.
7. §8 item 9: do you want the conditional write of `lastKeyId` in the code?

## 10. Round 3 (2026-10-22): the design the model now checks

**Status:** written before the round 3 model was generated or run. Spec 002
round 3 (D34–D43) changes the protocol in exactly the places §7's expected
failures pointed at, and adds an email-code path. This section is the IR
for that design, in the same fields; `device.spthy` is regenerated from it.
§1–§9 above stay as the record of round 2 (its findings are what round 3
answers), and every round 2 mechanism round 3 removes is kept in the model
as a **mutant variant**, so the model shows that each round 3 mechanism is
what makes its property hold.

### 10.1 What changes, item by item

| # | Item | Round 3 | Contract | Confidence |
|---|---|---|---|---|
| R1 | Factor signing key | The factor also has `fsk(fs, 'f1')`, a signing key derived from its secret; its public half is registered at Mail with the factor key (`!MailFactorKey` now holds both). | A2b | HIGH |
| R2 | Transition | A rotating page that holds the factor signs `<'transition', m, pk_old, pk_new>` with `fsk`. The action `FactorAuthorized(m, pk_old, pk_new)` marks it. | A11 | HIGH |
| R3 | Walk step (W1) | A successor step is taken only with that transition, signed by the trusted factor. A stateless page trusts the factor it used; a kept device trusts the factor it was kept with (its record names it). | K2″ | HIGH — one factor, so "the trusted component" is that factor (P3 of §1 stands). |
| R4 | Recipients (T3/T4) | A device record is sealed to only with an admission signed by the factor and an unlock-key statement signed by the device's own signing key; a factor record only with the factor's admission. Tags are not checked in the base model (they are a second check in the system, and §7's argument no longer rests on them). | A11, K3′ | MEDIUM — dropping tags from the base model is a simplification; they only remove attacker options, so a "hold" carries over. |
| R5 | Bound factor proof | Every factor challenge carries `h(request)` and is answered only inside the honest rule that sends that request: rotation (`<'rotate', m, pk_old, pk_new>`), registration (`<'register', m, did, pkS>`), and a deviceless session (`<'open-session', chid>`). Mail applies a request only with a proof bound to it. The round 2 variant `BOUND_PROOFS` becomes the base. | A6, A10, D36 | HIGH |
| R6 | Mail checks the transition | Mail applies a rotation only with the transition signed by the registered factor signing key. | B7 step 2, M23 | HIGH |
| R7 | Mail's device registry | Mail's honest records gain the registered devices (`MailDevice`, a linear fact): created by a registration with a bound factor proof, consumed by a revocation. A device session needs the device in the registry. | B7, B7a | MEDIUM — round 2 read the device's key from the store (§8 item 10); round 3 needs the registry to say what revocation does. The registration does not also require a session in the model (more permissive, so a "hold" carries over). |
| R8 | Deviceless session | A session without a device needs the key proof **and** a factor proof bound to that session challenge. | B6, D38 | HIGH |
| R9 | Email-code revocation | The attacker may revoke any registered device at any time (the email-only actor is the attacker: whoever reads the owner's email). It consumes the device's registry entry and writes no key. | B7a, D35 | HIGH — the rule gives the attacker the whole email path; nothing in it can make a key. |

Unchanged: lock timers, labels, expiry (§8 items 1, 5, 6); several factors
(§8 item 4: still one); the account check (D37) is a browser-local read of
the right record and is outside a one-account model; the compare-and-swap of
`lastKeyId` (A2) is now what the code does too (D41, K11).

### 10.2 Mutant variants (each removes one round 3 mechanism)

| Variant | Removes | Its property should then fail with the attack of |
|---|---|---|
| `-D=NO_TRANSITION_SIG` | R3: the walk takes a successor step on the successor seal alone (round 2) | §7 (ii) finding 1, the fork |
| `-D=NO_ADMISSION` | R4: recipients are sealed to on a tag under the old key (round 2) | §7 (iii) finding 2, the planted recipient |
| `-D=MAIL_UNCHECKED` | R5 and R6 at Mail: a rotation is applied on an unbound factor proof, without the transition; the owner answers any factor challenge | §7 (i) finding 3, the relay's rotation |
| `-D=EMAIL_ROTATES` | D35: Mail also applies a rotation confirmed by an email code (the attacker can produce one) | the email-only actor rotating to a key it knows |
| `-D=KEY_ONLY_SESSION` | R8: a deviceless session opens on a key proof alone (round 2) | a revoked device that copied the key reopening a session |
| `-D=ORACLE_MUTANT` | K4 (unchanged from round 2) | §7 (v) |

### 10.3 Proof targets, with the verdict expected before running

| Lemma | Says | Expected (base) | Expected (mutant) | Why |
|---|---|---|---|---|
| `factor_secret` | the factor secret and both factor private keys never reach the attacker | hold | — | never sent; now also `fsk` |
| `successor_authored_by_factor` | every rotation Mail applies was signed, for exactly that pair of keys, by the factor holder, earlier — whatever devices are compromised, and with the email path open | hold | fail under `MAIL_UNCHECKED` and `EMAIL_ROTATES` | Mail needs the transition under `fsk` (R6) and a proof bound to the same pair (R5); only the factor holder makes either |
| `accepted_step_authored_by_factor` | every successor step a browser takes was authorized by the factor holder — whatever devices are compromised | hold | fail under `NO_TRANSITION_SIG` | the walk needs the transition (R3) |
| `accepted_key_is_honest_stateless`, `accepted_key_is_honest_kept` | a key a browser accepts was made by an honest page of the mailbox — **with no restriction on compromise** (round 2's `chain_agreement_*` needed "no compromise" or failed) | hold | fail under `NO_TRANSITION_SIG` | a step to an attacker's key needs a transition the attacker cannot sign; with no step, the key is the factor's own wrap or the device's last accepted key |
| `sealed_only_to_admitted_recipients` | a rotating page seals the new key only to a recipient an honest party made, or to a device that is itself compromised (and never to the device being removed) — whatever devices are compromised | hold | fail under `NO_ADMISSION` | a record needs the factor's admission and the device's own unlock-key signature |
| `factor_proof_bound` | a factor proof Mail accepts was given by the owner for exactly that request, once | hold | fail under `MAIL_UNCHECKED` | R5 |
| `revoked_device_opens_no_session` | after a device is revoked by email, no device session opens for it | hold | — | the registry entry is consumed (R7, R9) |
| `session_needs_owner` | every session Mail opens was opened by a registered device's signature or with the owner's factor answer bound to it | hold | fail under `KEY_ONLY_SESSION` (with a compromised device's key) | R8 |
| round 2's `mailbox_key_secret`, `dek_secret_honest_key`, the post-removal secrecy lemmas, `kept_device_no_rollback` | as §7 | hold (each one §7 expected to fail now expected to hold) | — | the inductions §4 describes are unchanged in kind; README records whether they terminate |
| sanity lemmas | the honest flows still run | trace exists | — | |

### 10.4 What the operator should check in this section

1. R4: is dropping tags from the base model acceptable (they stay in the
   system as a second check)?
2. R7: is "registration without a session" an acceptable over-approximation
   of Mail's registry?
3. R9: the attacker may revoke at any time; is "the email-only actor is the
   whole network attacker" the question you want answered?
4. 10.3: does each "hold" state what the spec promises in §4's rows
   (round 3)?
