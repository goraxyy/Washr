# Spaceona — Audit Tickets

A cross-repository audit of the Spaceona laundry-monitoring system: **51 findings** across the
firmware, the Go API, the legacy Node server, and the React app.

| Severity     | Count | Meaning                                                        |
| ------------ | ----: | -------------------------------------------------------------- |
| **Critical** |     8 | Exploitable now, no credentials required                        |
| **High**     |    11 | Security weaknesses, or core function is broken                 |
| **Medium**   |    22 | Correctness, reliability, data integrity                        |
| **Low**      |    10 | Small defects and dead code                                     |

**ID prefixes** — `FW` Washr firmware · `GO` backend-go · `NS` spaceona-db-server ·
`FE` washr-frontend-react · `OPS` repository and deployment hygiene.

> **Note on redaction.** Findings OPS-01 and GO-12 concern live credentials. Because this file
> lives in a public repository, the key values are shown truncated. The exact values are
> recoverable from the artefacts named in each ticket; see OPS-01 for the command. Treat all
> four keys as compromised regardless of what this file shows.

---

## Contents

- [How the system works](#how-the-system-works)
- [The unauthenticated attack chain](#the-unauthenticated-attack-chain)
- [Critical](#critical)
- [High](#high)
- [Medium](#medium)
- [Low](#low)
- [Suggested fix order](#suggested-fix-order)

---

## How the system works

An ESP32-C3 board is attached to each washer/dryer, reads an accelerometer, decides whether the
machine is vibrating, and reports one boolean. A backend stores it. Students see which machines
are free.

There are two generations, and both are deployed:

- **Gen 1** — firmware `1-0-0`–`1-2-x` posted *raw* accel/gyro JSON to `spaceona-db-server`,
  which ran detection server-side and wrote to Firestore.
- **Gen 2** — firmware `1-6-x` decides on-device and posts only a boolean to `backend-go`,
  which keeps SQLite for history and Redis as the read cache. `washr-frontend-react` polls it.

**Device path.** Boot → NVS init → IMU init → 100 ms motion debouncer (counter crosses 30 →
`Active`) and a 5 s network state machine (`Start → getCreds → wifiInit → Setup → Authenticate →
Transmit`) → `POST /onboard/board` once → `POST /auth/device` for a 24 h JWT → `POST
/status/update` on a flip, plus a heartbeat every minute → OTA check on its own timer.

**Server path.** `/status/update` behind `auth.Middleware`, branching on `StatusChanged`:
true → `UPDATE machine` + `INSERT StatusChange` + Redis write; false → Redis refresh only.
Reads hit `/status/{client}/{building}/{type}/{machineId}`, fill missing segments with `*`,
and `SCAN` Redis. No SQL on the read path.

---

## The unauthenticated attack chain

Four findings compose into full write access with no credential at any step.

```
# 1. Harvest every board MAC. This is the exact request the student app makes on
#    page load. No auth, and the trailing slash widens it to every client (FE-01).
GET /status/lafTest/
    -> {"Statuses":{"1":{"mac_address":{"String":"24:EC:4A:D7:0F:70",...},...}, ...}}

# 2. Trade a MAC for a 24-hour JWT. No secret is checked: the handler selects
#    `valid` and never reads the variable it scanned into (GO-02).
POST /auth/device   {"mac_address":"24:EC:4A:D7:0F:70","firmware_version":"1-6-5"}
    -> {"Token":"eyJhbGciOiJIUzI1NiIs..."}

# 3. Write any machine's status. The handler trusts the mac_address in the BODY
#    and never compares it to the one inside the token (GO-05).
POST /status/update   Authorization: Bearer <token>
     {"mac_address":"<any other board>","Status":true,"StatusChanged":true}
    -> 200

# ...and if step 1 were closed, step 2 is still reachable: onboarding never stops
#    on a bad client key, so any MAC can be registered as valid (GO-01).
POST /onboard/board   {"mac_address":"AA:BB:CC:DD:EE:FF",
                       "client_name":"lafTest","client_key":"wrong"}
    -> 200 "Successfully onboarded device!"      <-- inserted with valid = 1
```

---

## Critical

### FE-01 — The public app hands out the fleet's board MAC addresses

- **Repo:** washr-frontend-react, backend-go
- **Location:** `src/api.js:7` · `backend-go/src/main.go:59-63` · `backend-go/src/helpers/types.go:23`

The app fetches `https://api.spaceona.com/status/lafTest/` — with a trailing slash. Go 1.22
wildcards match one *non-empty* segment, and a pattern not ending in `/` will not match a
trailing slash, so `/status/{client}` does not match this URL. The subtree pattern `/status/`
does. `PathValue("client")` returns `""`, the handler substitutes `"*"` for all four filters,
and the response contains **every machine of every client**. The `lafTest` segment is inert.

The serialised `DBMachine` includes `mac_address`. So the single unauthenticated request every
visitor's browser makes on page load returns the MAC of every board in the fleet — and per
GO-02, a MAC is the only thing needed to mint a 24-hour device token.

Verify (the two should differ):

```bash
curl -s 'https://api.spaceona.com/status/lafTest/' | jq '.Statuses | length'
curl -s 'https://api.spaceona.com/status/lafTest'  | jq '.Statuses | length'
```

**Fix.** Drop `mac_address` from the public response — the app never reads it. Remove the bare
`/status/` route or make it reject an empty client, and drop the trailing slash in `api.js`.
Longest term, stop treating a MAC as a secret (GO-02).

### GO-01 — Onboarding continues after the client key fails

- **Repo:** backend-go
- **Location:** `src/admin/onboarding.go:69-73`

The key comparison writes a `400` and then falls straight through into the `INSERT`, because
the `return` is missing. Any MAC can be registered as a valid board for any client, with any
key or none.

```go
if clientCheck != dbCheck {
    http.Error(w, "could not onboard device", http.StatusBadRequest)
}   // <-- no return; execution continues
newBoardSqlString := "INSERT INTO board (mac_address, valid, client_name) VALUES (?,?,?);"
```

**Fix.** Add `return`. Use `subtle.ConstantTimeCompare` for the comparison, and add a test that
a wrong key produces no row.

### GO-02 — Device auth requires only a MAC address

- **Repo:** backend-go
- **Location:** `src/auth/BusinessLogic.go:12-47`

Two defects compound. The request struct has no `ClientKey` field, so the key the firmware
sends is silently discarded by the JSON decoder. And the handler queries `SELECT valid`, scans
it into a variable, and never checks it — a revoked board authenticates like a live one. A MAC
address is a public identifier: printed on the board, broadcast in every Wi-Fi frame, and
returned by two public endpoints (FE-01).

```go
type AuthDeviceRequest struct {
    MacAddress      string `json:"mac_address"`
    FirmwareVersion string `json:"firmware_version"`
}   // client_key from the firmware is dropped here

var valid bool
rowScanErr := row.Scan(&valid)   // ...and `valid` is never read again
token, tokenErr := GenToken(AuthDeviceRequest, 24*time.Hour)
```

**Fix.** Add `ClientKey` to the struct, verify it against the stored hash, and reject when
`valid` is false. Devices should hold a per-device secret, not a per-client one.

### GO-03 — Admin and onboarding endpoints have no authentication

- **Repo:** backend-go
- **Location:** `src/main.go:54-58`

`/admin/device/valid` and `/admin/machine/new` are wrapped in `logging.Middleware` *twice*
where the outer should be `auth.Middleware`. The neighbouring line shows the intended shape.
Both onboarding routes are unauthenticated too. Anyone can mark every board invalid — a
fleet-wide denial of service — or inject machines.

```go
http.Handle("/admin/machine/assign", auth.Middleware(logging.Middleware(...)))
http.Handle("/admin/device/valid",  logging.Middleware(logging.Middleware(...)))  // auth missing
http.Handle("/admin/machine/new",   logging.Middleware(logging.Middleware(...)))  // auth missing
```

**Fix.** Wrap all four admin routes in `auth.Middleware` and add a role check — device tokens
must not reach admin handlers. Onboarding needs its own operator credential.

### GO-04 — SQL injection in the machine insert

- **Repo:** backend-go
- **Location:** `src/admin/onboarding.go:168-177`

Every other query in the codebase is parameterised; this one builds SQL with `fmt.Sprintf` and
`%s` for client name, building name and machine type. It is reachable from `/onboard/client`
and `/admin/machine/new`, both unauthenticated per GO-03.

```go
sb.WriteString(fmt.Sprintf("(%d,'%s',NULL,'%s','%s',0),",
    machine.Number, clientName, building.BuildingName, machine.Type))
```

**Fix.** Build the placeholder list dynamically and pass values as arguments.

### FW-01 — TLS verification disabled, and OTA images are unsigned

- **Repo:** Washr
- **Location:** `src/WifiFunctions.cpp:93, 339-369`

`client.setInsecure()` turns off certificate validation for every request the board makes — the
pinned certificate above it is commented out with a note that it "isn't working". That same
`WiFiClientSecure` is then handed to `httpUpdate.update()`, which streams whatever comes back
directly into the OTA partition and reboots. There is no image signature and no manifest hash.

Anyone able to intercept the connection — the campus network, a rogue AP, DNS — serves their own
binary and gains permanent code execution on every sensor in the building. The board cannot
distinguish this from a legitimate update.

```cpp
// client.setCACert(test_root_ca);
// Not sure why the cert isnt working, but it does work insecurely
client.setInsecure();   // <-- and this client carries the OTA image
```

**Fix.** The commented certificate expired in September 2024, which is why it failed — pin the
Google Trust Services *root*, not the leaf, so it survives renewal. Independently, enable ESP32
secure boot and signed OTA so a bad certificate is not a code-execution bug.

### OPS-01 — Live credentials are published in the firmware binaries

- **Repo:** backend-go (artefacts), Washr (source of the values)
- **Location:** `firmware/1-6-1..1-6-5.bin`, `firmware/1-0-0.bin`,
  `Bruno/spacesona/onboardBoard.bru:17`, `migrations/dummyData.sql:3`

The Washr README is explicit that `wifi_secrets.h` must never be committed. It never was — but
the compiled artefacts that *embed* its contents were, to a public repository, and are also
served by `/firmware/file/{version}`. A single `strings` run recovers them:

```bash
strings firmware/1-6-5.bin | grep -A2 'America/New_York'   # CLIENT_KEY, CLIENT_NAME
strings firmware/1-0-0.bin | grep 'token='                 # legacy AUTH_TOKEN
```

Four credentials are exposed (values truncated deliberately — see the note at the top):

| Credential            | Prefix   | Length | Where                                    |
| --------------------- | -------- | -----: | ---------------------------------------- |
| `CLIENT_KEY` (laf-test) | `Oojd…` |     25 | `firmware/1-6-1` … `1-6-5.bin`           |
| Legacy `AUTH_TOKEN`   | `NpLv…`  |     48 | `firmware/1-0-0.bin`, inside a URL query |
| Client key (`wpi`)    | `COO1…`  |     25 | `Bruno/spacesona/onboardBoard.bru`       |
| Client key (`lafTest`)| `5J*P…`  |     25 | `migrations/dummyData.sql`               |

All four match the 25-character alphabet in `auth.randPassword`, so these are generated keys,
not placeholders. The leaked `AUTH_TOKEN` is the only credential protecting the legacy server's
metrics (see NS-01).

**Fix.** Rotate all four now. Move device secrets out of the compiled image into NVS provisioned
at flash time, stop committing binaries to git, and serve firmware from object storage.
Rotating alone is not enough while the build still bakes keys into the image. Note that removing
the binaries from `HEAD` does not remove them from history.

### NS-01 — The legacy server's write and export routes have no auth

- **Repo:** spaceona-db-server
- **Location:** `src/index.ts:27-29`, `src/dump.ts`, `src/update.ts`

`authMiddleware` is applied inside `metrics.ts` only. `/update` and `/dump` are mounted with no
middleware at all, while `apidocs.md` states that "all API requests require authentication via a
token". Documentation and implementation disagree, and the implementation is what ships.

`/update` writes to Firestore, which is what the student app reads — anyone can set any machine
in any building to any status. `/dump/:machineid` exports raw sensor history as CSV to anyone.

**Fix.** Apply `app.use(authMiddleware)` to both routers. Move the token out of the query string
into an `Authorization` header — query parameters land in access logs, proxy logs and browser
history, which is how `1-0-0.bin` ended up carrying one in a URL.

---

## High

### FE-02 — One failed poll blanks the entire page

- **Repo:** washr-frontend-react
- **Location:** `src/api.js:31-34` · `src/pages/Home.jsx:14-22`

`fetchMachineStatuses` catches every failure — network error, 500, CORS rejection, malformed
JSON — and returns `[]`. `Home` assigns that unconditionally. So a single transient failure on
the 30-second poll replaces a full machine list with "No machines found", which is also exactly
what a healthy laundry room with no registered machines looks like. No error state, no retry, no
stale-while-error.

The mapping step is the more fragile half. It reaches into `machine.type.Valid` with no guard,
so *one* machine whose `type` is absent throws a `TypeError` inside `.map`, which the same catch
swallows into an empty array. One bad row takes down the whole page — and GO-20 produces exactly
such a row.

**Fix.** Return a discriminated result rather than `[]`, keep the last good list on failure, and
render a distinct "can't reach the server" state. Guard the field access, or fix the wire format
(FE-03) so the guards are unnecessary.

### GO-05 — The token is never bound to the device it authenticates

- **Repo:** backend-go
- **Location:** `src/status/updateStatus.go:35-61`

`GenToken` puts the whole `AuthDeviceRequest` — MAC included — into the JWT claims, but
`UpdateStatusRoute` reads `mac_address` from the request body and never compares the two. Any
board with a valid token can write any other board's status. This is step 3 of the attack chain
and turns one compromised sensor into control of the whole fleet.

**Fix.** Have the middleware put parsed claims in the request context, and have the handler use
the MAC from the token, ignoring the body's copy entirely.

### GO-06 — An unset JWT_SECRET silently produces forgeable tokens

- **Repo:** backend-go
- **Location:** `src/auth/auth.go:16-37`

`os.Getenv("JWT_SECRET")` returns `""` when the variable is absent, and both signing and
verification proceed with an empty HMAC key — every token becomes forgeable by anyone who knows
the payload shape. Nothing validates the secret at startup.

Separately, `jwt.Parse` is called without `jwt.WithValidMethods`. golang-jwt v5 will not accept
`alg: none` against a `[]byte` key, so this is hardening rather than a live break, but the
allowlist belongs there.

**Fix.** Fail fast at boot if `JWT_SECRET` is empty or under 32 bytes, and pass
`jwt.WithValidMethods([]string{"HS256"})`.

### GO-07 — MIGRATE=true drops every table and loads dummy data

- **Repo:** backend-go
- **Location:** `src/main.go:31-36` · `migrations/0-init.sql:1-5`

`0-init.sql` opens with five `DROP TABLE IF EXISTS` statements, and `main.go` calls `Migrate()`
then `DummyData()` unconditionally on that flag. One stray environment variable in production
destroys all machines, boards, clients and history, then seeds fictional Lafayette and WPI
records in their place. `runSqlFile` also splits on `;` with no awareness of string literals or
triggers.

**Fix.** Adopt a real migration tool with versioned up files and a schema table. Never ship
`DROP` in an automatically applied migration, and gate dummy data behind a separate flag.

### GO-08 — The staff OAuth flow is broken and leaks Google tokens

- **Repo:** backend-go
- **Location:** `src/auth/oauth.go:23-104`

Four problems in one flow:

1. No `state` parameter, so the callback is open to login CSRF.
2. The signed token is generated, written to the log with `slog.Info(spaceonaToken)`, and then
   **never assigned** to `token.tokenString` — so the cookie is set with an empty value and no
   one is ever actually logged in.
3. The struct it wraps embeds Google's access *and refresh* tokens. A JWT is signed, not
   encrypted, so anyone holding the cookie could read them.
4. The cookie's `Domain` is hardcoded to `localhost`, and the `TODO: check if the user is an
   admin` is still open.

**Fix.** Add and verify `state`; assign the generated token before setting the cookie; stop
logging tokens; keep Google credentials server-side keyed by session id; take the cookie domain
from configuration; implement the admin check before wiring these routes to anything.

### NS-02 — Stored XSS in the metrics dashboard

- **Repo:** spaceona-db-server
- **Location:** `src/metrics.ts:116, 336` · `src/update.ts:41-65`

`machineId` is built from the `:school` and `:building` path segments of `/update`, which are
never validated — only `type` and `id` are. It is stored, then interpolated raw into HTML:
``html += `<h2>Machine ID: ${machineId}</h2>` ``. The `/metrics/:id` route reflects its parameter
the same way.

Because `/update` is unauthenticated (NS-01), an attacker stores a payload that fires whenever
staff open the dashboard — and the dashboard is the one place the leaked `AUTH_TOKEN` is used.

**Fix.** Escape on output, or use Hono's JSX rendering which escapes by default. Constrain
`school` and `building` to a known-safe character class at the route boundary.

### GO-09 — The firmware version comparator is not a valid ordering

- **Repo:** backend-go
- **Location:** `src/firmware.go:99-116`

The comparator returns `1` as soon as *any* component of A is lexicographically greater than
B's, without first establishing that the higher-order components are equal. It reports that
`1-6-5` is newer than `2-0-0`, because `"6" > "0"` is reached after `"1" > "2"` fails.
Comparison is string-based, so `1-10-0` also sorts below `1-9-0`. `slices.SortFunc` with an
inconsistent comparator gives an arbitrary order, and `versions[0]` is what the whole fleet is
told to install.

`getAllVersions` compounds it by taking every file regardless of extension, so the committed
`1-1-0.elf` is offered as a version whose `.bin` does not exist.

**Fix.** Parse the three components to integers and compare in order, returning at the first
difference. Filter to `.bin`. A table test over `1-2-0 / 1-10-0 / 2-0-0` catches both defects.

### GO-10 — /firmware/latest panics on an empty directory

- **Repo:** backend-go
- **Location:** `src/firmware.go:51-61`

`versions[0]` is indexed with no length check, so an empty or unreadable `./firmware` panics the
goroutine. `getAllVersions` also runs before the method check, so a `HEAD` or `POST` does the
directory walk before returning 404.

**Fix.** Return `503` when the list is empty, and move the method check to the top.

### GO-11 — Unvalidated path segment reaches the filesystem

- **Repo:** backend-go
- **Location:** `src/firmware.go:19-22`

`filepath.Join("./firmware", r.PathValue("version") + ".bin")` takes the wildcard straight to
`os.ReadFile`. Go 1.22's `ServeMux` cleans `..` in the raw path and matches a single segment,
which blocks the naive attempt — but it unescapes each segment after matching, so a
percent-encoded separator can put a `/` inside `PathValue`. Not confirmed by execution against
this build, and the `.bin` suffix limits what is reachable regardless. It should not depend on
mux internals either way.

**Fix.** Reject anything not matching `^\d+-\d+-\d+$` before touching the path.

### FW-02 — OTA check runs every five minutes, not nightly

- **Repo:** Washr
- **Location:** `src/WifiFunctions.cpp:384-419`

The 3 AM scheduling block is commented out and replaced with `tm.Minute += 5`, marked as a debug
change. The CHANGELOG records the same drift — 3 AM, then hourly, then per-minute "for remote
development purposes". Every deployed board now polls `/firmware/latest` roughly 288 times a day,
and any update lands mid-cycle rather than overnight. A board rebooting into new firmware while a
machine is running loses that run.

**Fix.** Restore the overnight schedule and put the short interval behind a build flag rather
than an edit. Add jitter so a fleet does not synchronise on one minute.

### GO-12 — Client keys are stored in plain text

- **Repo:** backend-go
- **Location:** `src/admin/onboarding.go:57-68, 137`

`ClientOnboardingRoute` inserts the raw key. Verification then hashes the *stored* key and
compares it to the hash of the submitted one — so the salt and SHA-512 do nothing except make
the code look like it hashes. A database read yields every client key directly.

**Fix.** Store only the hash. Since these are high-entropy generated keys rather than user
passwords, a salted SHA-256 is acceptable, but compare in constant time and never store the
original.

---

## Medium

### FE-03 — The app parses Go's database types off the wire

- **Repo:** washr-frontend-react, backend-go
- **Location:** `src/api.js:23-26` · `backend-go/src/helpers/types.go:20-30`

`DBMachine` stores its nullable columns as `sql.NullString`, which marshals to
`{"String":"Washer","Valid":true}`. The API returns that shape verbatim, so the React client is
written against it: `machine.type.Valid ? machine.type.String : "Unknown"`. The frontend is
coupled to the backend's ORM internals — swapping `sql.NullString` for a pointer, which is the
idiomatic fix for several other findings here, silently breaks the app.

**Fix.** Give the status route its own response struct with plain `string` fields and an explicit
`offline` flag, and convert at the boundary.

### FE-04 — Machines render in string-sorted order

- **Repo:** washr-frontend-react, backend-go
- **Location:** `src/api.js:20` · `backend-go/src/status/getStatus.go:16`

`Statuses` is a `map[int]DBMachine`. Go's JSON encoder sorts map keys as strings, and
`Object.values` preserves that order, so the cards come out 1, 10, 11, 12, 2, 3. Invisible below
ten machines; the backend's own comment puts the deployment at roughly 150.

**Fix.** Sort by `number` within `type` in the client, or return an ordered array.

### FE-05 — The header claims Watson Hall for whatever the API returned

- **Repo:** washr-frontend-react
- **Location:** `src/components/TopBar.jsx:21` · `src/pages/Home.jsx:45-52`

`<h2>Watson Hall</h2>` is hardcoded, and the response — per FE-01 — carries every building of
every client. `api.js` extracts `building` and `client_name` for each machine and then `Home`
passes neither to `MachineStatus`, so machines from other buildings and other universities are
rendered under a Watson Hall heading with nothing to distinguish them. Two machines numbered 1 in
different buildings appear as two identical cards.

**Fix.** Group the cards by building and label each group from the data. The fields are already
fetched and discarded.

### FW-03 — "Machine finished" is never written to the database

- **Repo:** Washr, backend-go
- **Location:** `src/TickFunction.cpp:146-150` · `backend-go/src/status/updateStatus.go:43`

The most consequential functional bug in the system, and it takes both repos to see. The firmware
assigns `previousMachineStatus = machineStatus` *before* the call, so the two arguments are
always identical and the wire field `StatusChanged` always equals `Status`:

```cpp
if (machineStatus != previousMachineStatus) {
    previousMachineStatus = machineStatus;                          // <-- assigned first
    int httpCode = machineStatusUpdate(machineStatus, previousMachineStatus);
}
```

The backend branches on that field: `if body.StatusChanged == true` runs the SQL update and the
history insert, `else` only refreshes the Redis cache. So a machine turning **on** sends
`true/true` and is persisted, while a machine turning **off** sends `false/false` and takes the
cache-only path. The `machine.status` column stays at 1 forever, and `StatusChange` records
starts with no stops — exactly the data the duration and busy-hour analytics depend on.

**Fix.** Send the real previous value, or rename the field to what it is. Then have the backend
derive "changed" server-side by comparing against the stored row rather than trusting a device
flag.

### GO-13 — Redis keys are written with Go struct syntax

- **Repo:** backend-go
- **Location:** `src/status/updateStatus.go:103` · `src/status/getStatus.go:43`

The write path formats `sql.NullString` fields with `%s`. `NullString` has no `String()` method,
so `fmt` prints the struct: the key becomes `client:{Lafayette true}:building:{Watson true}:...`.
The read path builds its pattern from plain path values, which never matches. Only the
all-wildcard query returns anything — which is the only reason FE-01's trailing slash makes the
app work at all.

**Fix.** Use `.String` on each field when building the key, and add a round-trip test that writes
a key and reads it back through the same pattern builder.

### GO-14 — Redis SCAN reads one batch and stops

- **Repo:** backend-go
- **Location:** `src/status/getStatus.go:44`

`rds.Scan(ctx, 0, pattern, 100)` is called once with cursor `0`, and the returned cursor is
discarded into `_`. `SCAN` guarantees only that a full iteration covers everything — a single
call returns an arbitrary, variable subset. The comment says roughly 150 machines, already past
the count hint, so machines will intermittently vanish from the app for reasons nothing logs.

**Fix.** Loop until the returned cursor is `0`, or keep a Redis set of live machine keys.

### GO-15 — Machine type is substituted for the MAC in the lookup key

- **Repo:** backend-go
- **Location:** `src/status/getStatus.go:23, 43` · `src/main.go:63`

The `Sprintf` passes `machineType` for both the type and machine positions — `macAddress` is
computed and then unused. And the route declares `{machineId}` while the handler reads
`r.PathValue("macAddress")`, which is always empty. The single-machine query cannot work.

**Fix.** Pass `macAddress` in the last position and align the route wildcard with the name the
handler reads.

### FW-04 — Seeed boards report motion continuously

- **Repo:** Washr
- **Location:** `src/MPUFunctions.cpp:209, 242`

`motion_detected` returns true if `abs(a.acceleration.z) >= MPU_ACCEL_Z_THRESH`, where the
threshold is `0.20` m/s². A stationary board reads about 9.81 on whichever axis faces down, so in
the mounting orientation the comments describe, this term is always true and the debounce counter
only ever climbs. The commit *"Changed detection to only be changed in accel"* removed this
absolute term from the ICM-42670 path in `IMUFunctions.cpp` but left the MPU-6050 copy untouched.

**Fix.** Drop the absolute-magnitude term to match the custom-board implementation. Better,
factor the shared debouncer into one file with a per-board sensor read — the two files are
otherwise line-for-line duplicates and will keep diverging.

### GO-16 — Offline detection is written but never called

- **Repo:** backend-go
- **Location:** `src/status/background.go`

`sensorStatusDaemon` has no caller and `checkIfSensorsOffline` is an empty body. A board that
dies mid-cycle leaves its last status in Redis for 30 minutes and then silently disappears, with
no distinction between "free", "unknown" and "sensor dead". The query in that file also selects
`StatusChange.mac_address` and `current_version`, columns the schema does not have — `0-init.sql`
defines `machine_id` and `firmware_version` — so it would fail if it were called.

**Fix.** Either implement it against the real schema on a ticker, or delete both functions so the
gap is visible. Surface an explicit `offline` state derived from `last_write`.

### FW-05 — Wi-Fi-loss transitions are immediately overwritten

- **Repo:** Washr
- **Location:** `src/TickFunction.cpp:231-259`

In both `Transmit` and `Authenticate`, the disconnection branch sets `Sensor_State = getCreds`
and then falls into an unconditional `if (!authenticated) ... else ...` that reassigns it. The
recovery path is unreachable; the board loops in `Transmit` instead, relying on the blocking
`wifiConnect()` retry inside the state body.

**Fix.** Make the second check an `else if`, or `break` out of the transition after handling
disconnection.

### FW-06 — A developer's LAN address is probed on every Wi-Fi init

- **Repo:** Washr
- **Location:** `src/WifiFunctions.cpp:100-107`

`client.connect("10.1.1.194", 3001)` is a leftover connectivity test against someone's local
machine. It runs on every network initialisation, blocks for the socket timeout on any network
where that address is not present, and — as the comment "change this later when it becomes a
problem" concedes — returns `true` either way, so it tests nothing. The address is visible in
every shipped binary.

**Fix.** Delete it. If a reachability probe is wanted, point it at `server_name` and act on the
result.

### FW-07 — NVS handles leak, and credentials are rewritten every boot

- **Repo:** Washr
- **Location:** `src/flashStorage.cpp:29-75` · `src/esp32code_v3.cpp:63`

Three functions return early on the `nvsInit` check without calling `flashStorage.end()`, leaving
the namespace open — and every function opens with `end()` then `begin()`, so the pattern depends
on that cleanup. `getWifiPassword` opens read-write where every sibling opens read-only.
Separately, `setup()` calls `setWifiCredentials(WIFI_SSID, WIFI_PASSWORD)` unconditionally, so
the compiled-in credentials are written to flash on every single boot, wearing the NVS partition
and defeating the stored-credential design the rest of the file implements.

**Fix.** Close the handle on every path — a small RAII guard removes the whole class of error.
Write credentials only when they differ from what is stored.

### FW-08 — Version parsing breaks at 10

- **Repo:** Washr
- **Location:** `src/globals.cpp:18-20` · `src/WifiFunctions.cpp:434-436`

`FIRMWARE_VERSION.substring(0,1)` and its siblings take exactly one character per component, in
both the local version and the server's reply. At `1-10-0` the minor version parses as `1`, and
the board concludes it is already newer than the update. Both sites carry a `TODO` saying so. At
the current `1-6-5` there are four releases of headroom.

**Fix.** Split on `-` and parse each component, in one shared helper used by both call sites.

### GO-17 — Building names are globally unique, and the insert is missing a parameter

- **Repo:** backend-go
- **Location:** `migrations/0-init.sql:33-37` · `src/admin/onboarding.go:162-166`

`building.name` is the primary key with no client scope, so the first university to register
"Watson Hall" takes that name from everyone else. The insert that would surface the clash passes
one argument for two placeholders — `Exec(newBuildingString, building.BuildingName)` — and is
written `INSERT OR IGNORE`, so the failure is swallowed twice over. Machines are then inserted
referencing a building row that was never created.

**Fix.** Make the key `(client_name, name)`, pass both arguments, and drop `OR IGNORE` so
conflicts are reported rather than absorbed.

### NS-03 — The detector reads state from a stale copy

- **Repo:** spaceona-db-server
- **Location:** `src/detection/isRunning.ts:36-70`

`isRunning` and `debouncedIsRunning` are destructured out of `currentState` at the top, then the
code below mutates `currentState` and continues reading the destructured copies. The
minimum-duration check therefore always evaluates against the previous call's values, so every
transition lags one sample. The `else` branch also resets `lastDebounceTimestamp` whenever the
reading matches, so an alternating signal can hold the debounce window open indefinitely and
never commit.

**Fix.** Read through `currentState` throughout, or compute the next state as a value and assign
once. The existing test suite runs the simulation but asserts nothing (NS-06), so neither defect
is caught.

### NS-04 — Usage sessions are paired across different machines

- **Repo:** spaceona-db-server
- **Location:** `src/metrics.ts:209-224, 52-70`

`/hourly` keeps a single `sessionStart` across a log stream that interleaves every machine, so a
start from machine A is closed by the next "not in use" row from machine B. The session is
attributed to A with a duration spanning both. The daily summary has the same flaw at line 60,
where it indexes `machineLogs[index + 1]` to find the end of a run. All published usage numbers
are wrong whenever more than one machine is active.

**Fix.** Group by `machineId` first, then walk each machine's series independently.

### NS-05 — Unbounded queries and unbounded memory, on unauthenticated routes

- **Repo:** spaceona-db-server
- **Location:** `src/metrics.ts:12-21, 195` · `src/update.ts:36` · `src/detection/isRunning.ts:17`

`/metrics` loads every log since February 2024 into memory with no limit, and `?hours=` is
unbounded. More seriously, `machineCache` and `machinesState` are plain objects keyed by
`machineId`, built from unvalidated path segments on the unauthenticated `/update` route — a loop
over distinct school names grows both maps without limit until the process dies, and writes a
database row per request on the way.

**Fix.** Validate `school` and `building` against known values, cap `hours`, paginate the metrics
queries, and give both caches a bounded LRU.

### GO-18 — CORS is wide open and preflight is unhandled

- **Repo:** backend-go
- **Location:** `src/helpers/cors.go`

`Access-Control-Allow-Origin: *` on every route, including authenticated ones. No
`Allow-Methods` or `Allow-Headers` is sent and no handler answers `OPTIONS`, so a browser
preflight for a request carrying `Authorization` reaches `auth.Middleware` without a header and
is rejected with `401`. Any browser client that needs an authenticated call cannot make one.

**Fix.** Answer `OPTIONS` before the auth check, send the method and header allowlists, and
replace `*` with a configured origin list.

### OPS-02 — .dockerignore uses underscores where it means asterisks

- **Repo:** spaceona-db-server
- **Location:** `.dockerignore:4-6`

The file reads `_.env`, `_-firebase-_.json`, `_.db` — the `*` characters are underscores,
matching nothing. Compare `.gitignore`, which has the patterns right. The builder stage runs
`COPY . .`, so `.env` and the Firebase admin service-account JSON enter the build context and
land in a builder layer. The multi-stage build means they are not in the final image, so this is
a hardening failure rather than a live leak — but the build cache holds them, and anyone building
with `--target builder` gets a Firestore admin key.

**Fix.** Correct the three patterns. Mount the service account as a runtime secret instead of a
file in the context.

### GO-19 — A missing .env spins the CPU forever

- **Repo:** backend-go
- **Location:** `src/main.go:23-29`

When `godotenv.Load()` fails, the process enters `for { }` — an empty busy loop, with the comment
"we loop here so I can pop a shell". It burns a core, never listens, and never exits, so Docker's
`restart: always` cannot help and every health check that only pings the container reports fine.

**Fix.** `log.Fatal`. Better, treat `.env` as optional and read configuration from the
environment, validating required keys at startup.

### OPS-03 — Build output and a database file are committed

- **Repo:** backend-go
- **Location:** `src/spacesona-go-backend`, `database.db-shm`, `.gitignore:3`

A 27 MB compiled Go binary and a SQLite shared-memory file are tracked. The `.gitignore` line
reads `*.db-shim`, a typo for `*.db-shm`, which is why the latter slipped through. Together with
the nine firmware images (OPS-01) this is about 45 MB of artefacts in a repository whose source is
under 3,000 lines.

**Fix.** Fix the pattern, remove all three classes from tracking, and add `*.db-shm` / `*.db-wal`.

### GO-20 — Status updates for unmapped boards write a phantom cache entry

- **Repo:** backend-go
- **Location:** `src/status/updateStatus.go:116-128`

`updateStatus` ignores the return of `row.Next()`. When the `UPDATE ... RETURNING` matches nothing
— a board with no machine assignment — `Scan` fails, the error is only logged, and the
zero-valued struct proceeds into `updateCache`, writing a key with empty client, building and
type at machine id `0`. The parallel `refreshCache` path handles this correctly by returning
`NotMappedError`, so the two branches disagree about the same condition. This is the row that
triggers FE-02.

**Fix.** Check `row.Next()` and return `NotMappedError`, matching the heartbeat path.

---

## Low

### FE-06 — The production API URL is hardcoded twice, and used once

- **Repo:** washr-frontend-react
- **Location:** `src/api.js:3, 7`

`const BASE_URL = "https://api.spaceona.com/status/lafTest/"` is declared and never referenced;
the same string is inlined into the `fetch` call four lines down. There is no `.env` and no
`import.meta.env` usage, so the app cannot be built against staging or a local backend without
editing source.

**Fix.** Read the base URL from `import.meta.env.VITE_API_BASE` with the production value as the
default, and delete the unused constant.

### FE-07 — Scaffolding and unused dependencies never cleaned up

- **Repo:** washr-frontend-react
- **Location:** `src/App.js`, `src/App.css`, `package.json:13-17`, `src/index.css`

`App.js` and `App.jsx` define the same component; `main.jsx` imports the `.jsx`, so the other is
dead. `App.css` is untouched Vite starter CSS — `logo-spin`, `.read-the-docs` — imported nowhere.
`axios` and `react-router-dom` are production dependencies, but the code uses `fetch` and has no
router. `index.css` defines `.machine-card`, `.machine-list`, `.status`, `.status.available` and
`.status.in-use` twice each, with different values for `.machine-card` — the second wins, so the
first block is silently dead.

**Fix.** Delete `App.js` and `App.css`, drop the two unused dependencies, and collapse the
duplicated CSS. Rename the package from `washr-frontend-temporary` if it is no longer temporary.

### FE-08 — Polling continues in hidden tabs, forever

- **Repo:** washr-frontend-react
- **Location:** `src/pages/Home.jsx:21`

`setInterval(loadMachines, 30000)` runs for the life of the mount with no `visibilitychange`
gating. A phone left on the page in a background tab keeps requesting every 30 seconds
indefinitely. With one endpoint doing an unpaginated Redis `SCAN` per call (GO-14), a lecture hall
of idle tabs is a meaningful share of the load.

**Fix.** Pause the interval when `document.hidden`, and refetch once on becoming visible again.

### FE-09 — Invalid CSS length, and a favicon typed as the wrong format

- **Repo:** washr-frontend-react
- **Location:** `src/index.css` · `index.html:5`

`font-size: 14 px` — a space between the number and the unit makes the declaration invalid, so it
is dropped and the feedback button inherits its size. And
`<link rel="icon" type="image/svg+xml" href="/Spaceona-Logo.png">` declares an SVG MIME type for a
PNG; browsers sniff and recover, but the SVG sitting beside it in `public/` is what the tag was
written for.

**Fix.** `14px`, and point the icon at the `.svg` or correct the type.

### FW-09 — A status change can be sent twice in one tick

- **Repo:** Washr
- **Location:** `src/TickFunction.cpp:139-150`

The retry block fires when the previous POST was not `200`, and the change block fires
immediately after when the status differs. On a tick where both hold, the board posts twice, and
the two requests race to set `previousHttpCode`. There is also no backoff — a failing server is
retried every five seconds indefinitely, which the `TODO` on line 141 anticipates.

**Fix.** Make the branches mutually exclusive and add exponential backoff with a cap.

### GO-21 — Response headers set after the status is written

- **Repo:** backend-go
- **Location:** `src/status/updateStatus.go:63-65` · `src/admin/onboarding.go:96-98`

`w.WriteHeader(http.StatusOK)` is called before `w.Header().Set("Content-Type", ...)`, so the
header never reaches the client. The body it sends is also not valid JSON:
`{message:"updatedDB"}` has an unquoted key.

**Fix.** Set headers first, and marshal the response from a struct like the other handlers do.

### GO-22 — Board.ClientName is typed bool

- **Repo:** backend-go
- **Location:** `src/helpers/types.go:12`

`ClientName bool` in a struct scanned from a `text` column, so `GetBoardInfoRoute` logs a scan
error for every row and returns partially populated boards.

**Fix.** Change to `sql.NullString`, matching the sibling structs.

### GO-23 — Request built before its error is checked

- **Repo:** backend-go
- **Location:** `src/auth/oauth.go:163-165`

`req.Header.Set(...)` runs on the line before `requestCreationError` is tested. If construction
fails, `req` is nil and the handler panics instead of returning the error it captured.

**Fix.** Move the error check above the header call.

### GO-24 — slog called with values and no keys

- **Repo:** backend-go
- **Location:** `src/db/database.go:30, 33` · `src/status/updateStatus.go:138-139`

Several calls pass a bare value where `slog` expects alternating key-value pairs, producing
`!BADKEY` in the output. Two of them log the database URL, which carries credentials in any
non-SQLite deployment — as does the `panic(dbconErr.Error() + dbName)` on line 34.

**Fix.** Add keys, and never log or panic with a connection string.

### NS-06 — The detection test asserts nothing

- **Repo:** spaceona-db-server
- **Location:** `src/detection/detection.test.ts:14-18`

`"Simulate Machine State"` runs the simulation over the CSV fixture and ends. With no `expect`, it
passes for any behaviour the detector might have — including NS-03. The README points contributors
at this suite as the way to validate changes to `isRunning.ts`.

**Fix.** Assert the expected transition count and timing against the labelled fixture. This is the
highest-value test in the repository if it actually checks something.

---

## Suggested fix order

Ordered by exposure, not effort. The first row is short work and closes the entire attack chain.

| When                  | What                                                                                                                                                                                              | Tickets                                  |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------- |
| **Today**             | Rotate the four leaked keys. Add the missing `return`, verify the client key and the `valid` flag on device auth, put `auth.Middleware` on the admin routes, drop `mac_address` from public status.  | OPS-01, GO-01, GO-02, GO-03, FE-01       |
| **This week**         | Parameterise the machine insert. Add auth to the legacy `/update` and `/dump`, and escape the dashboard HTML. Bind the status token to its device.                                                   | GO-04, NS-01, NS-02, GO-05               |
| **Before next flash** | Restore certificate pinning against the root, and put the OTA check back on an overnight schedule. Fix the version comparator — it decides what every board installs.                                | FW-01, FW-02, GO-09, GO-10               |
| **Next sprint**       | Repair the status pipeline end to end: the `StatusChanged` semantics, the Redis key format, the SCAN loop. Nothing downstream is trustworthy until these land together.                              | FW-03, GO-13, GO-14, GO-15               |
| **Frontend pass**     | Make failure visible instead of empty, give the status route its own response type so the app stops parsing `sql.NullString`, and label cards with the building they came from.                      | FE-02, FE-03, FE-05                      |
| **Structural**        | Signed OTA images, per-device secrets provisioned at flash time rather than compiled in, a real migration tool, and offline detection that actually runs.                                            | FW-01, OPS-01, GO-07, GO-16              |

---

## A note on the pattern

The recurring shape is **work that was started, verified by hand once, and never closed**. The
client key is hashed and compared — but the mismatch does not stop the insert. The `valid` column
is selected — but never read. Certificate pinning is written out in full — but commented out with
a note that it did not work. The offline daemon exists — but nothing calls it. The detection test
runs — but asserts nothing. The frontend extracts `building` and `client_name` — then discards
them. Every one of these is a few lines from correct, and the `TODO` comments show the authors
knew.

The architecture is sound: on-device detection with a cache-backed read path is the right shape
for this problem. What is missing is the last inch on each piece, and a test that would have
noticed.

The single highest-leverage change is not on the list above: **an integration test that boots the
API, onboards a board with a wrong key, and asserts that no row appears.** That one test fails
against three separate critical findings today.
