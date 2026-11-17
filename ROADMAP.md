# SpaceOna roadmap

Every planned improvement across the SpaceOna repos, as one checklist. It lives in the Washr
repo because firmware is where most of the work starts, but it covers the backend, the website and
the board too.

**Tick an item** by changing `- [ ]` to `- [x]`, on GitHub (pencil icon) or locally, and commit.

Ticket IDs such as `FW-03` point to the September audit in `TICKETS.md` on the
[`docs/audit-tickets`](https://github.com/goraxyy/Washr/blob/docs/audit-tickets/TICKETS.md) branch.
Nothing below has reached the Spaceona org repos yet: each item goes there as a pull request once
the team agrees.

Last updated: 17 November 2026.

## Done, waiting on fork branches

- [x] Local test setup: the backend in Docker, 12 fake boards and a stand-in API (laptop only)
- [x] Status page redesign, covering FE-02, FE-04, FE-05, FE-06 and FE-08
      (washr-frontend-react `ui/status-page-redesign`)
- [x] API address as a setting (washr-frontend-react `sandbox/configurable-api-base`)
- [x] Watchdog that opens a GitHub issue when the API or the sensors fail (private repo)
- [x] Backend security fixes (backend-go `security/fix-critical-auth`)
- [x] Firmware CI and a flash overflow fix (Washr `ci/run-on-pull-requests`)
- [x] 51-finding audit (Washr `docs/audit-tickets`)
- [x] Beginner hardware guide and JLCPCB parts files (WashrBoard `docs/beginner-hardware-guide`)

## 1. Keep the sensors online (first)

- [ ] Find what caused the 14–16 November outage: power unplugged, or a board hang. Ask who
      reset the boards on 16 November and what they found.
- [ ] Report the boot reason (power-on, crash, watchdog, brownout) in the first status after
      every start, so the next outage can be traced afterwards
- [ ] Boards restart themselves: a hardware watchdog plus a reboot after a few minutes without
      Wi-Fi (see FW-05)
- [ ] Protect the power: label the plugs, secure the cords, and decide on a smart power strip
      for remote power-cycling
- [ ] Bring Reeder Washer 1 back online
- [ ] Trigger the watchdog from an outside scheduler (GitHub ran the 30-minute schedule only
      6 times in 48 hours)

## 2. Status data and backend

- [ ] Save "machine finished" events (FW-03) and repair the status pipeline (GO-14; GO-13 and
      GO-15 are on the security branch)
- [ ] Turn on offline detection (GO-16)
- [ ] Stop "database is locked" errors when boards report at the same moment
- [ ] Stop caching an entry for a board that isn't mapped (GO-20)
- [ ] Check for new firmware once a day instead of 288 times (FW-02)
- [ ] Give the status route plain JSON types (FE-03)
- [ ] Get Spaceona/backend-go#7 merged so org main matches what runs in production
- [ ] Remaining backend tickets: GO-09, GO-10, GO-11, GO-18, GO-21, GO-22, GO-23
- [ ] Remaining firmware tickets: FW-04, FW-06, FW-07, FW-08, FW-09
- [ ] Remaining ops tickets: OPS-02, OPS-03

## 3. Security

- [ ] Review the backend security branch with Kashif, set `ADMIN_API_KEY`, plan the board
      firmware change it needs, then deploy
- [ ] Finish FE-01: the security branch fixes the status route, but the info routes still
      return board identifiers
- [ ] Firmware: FW-01 and OPS-01, one secret per board instead of one shared key
- [ ] Rotate every secret the audit found in git history or in published binaries
- [ ] One SSH login per person on the server
- [ ] Scheduled SQLite backups, kept off the server
- [ ] Decide whether the legacy Node server (spaceona-db-server) still runs: retire it, or fix
      NS-01 to NS-06

## 4. Releases

- [ ] CI on every pull request in every repo (backend and firmware are on fork branches; the
      website has none yet)
- [ ] Automatic deploy with a health check and rollback
- [ ] A staging copy of the API

## 5. Website features

- [ ] Notify me when a washer is free
- [ ] Busy hours per building (needs FW-03)
- [ ] Time remaining, estimated from past cycles (the API's estimate is always -1 today)
- [ ] Per-building links and QR stickers on the machines
- [ ] Team page: each board's last report and firmware version
- [ ] Remaining website tickets: FE-07, FE-09

## 6. Circuit board (after WashrBoard v5.3)

- [ ] Swap Extended parts for Basic ones where possible (10 of the 17 parts are Extended), such
      as 0603 passives instead of 1206
- [ ] Use a 3-axis accelerometer instead of the 6-axis motion sensor
- [ ] Connect the sensor's interrupt pin so the chip can wake on vibration
- [ ] Try a module with the antenna on the board; test reception among the machines first
- [ ] Guard the two power inputs with a diode, or drop one
- [ ] Shrink the 70 × 50 mm board and design a case with a rigid mount (holes on a 62 × 42 mm
      pattern)

## 7. Access

- [ ] Get my own server account: send my public SSH key, get the server address
- [ ] Find out who holds the Cloudflare account and the website host

## 8. Explore: other uses for the board

- [ ] Gym: treadmills, bikes, ellipticals and rowers
- [ ] Makerspace: 3D printers and the laser cutter ("your print finished")
- [ ] Shared kitchens: dishwashers and microwaves
- [ ] Facilities: early warning from changes in how a machine vibrates
- [ ] Study rooms: needs a presence sensor (see the org's `studyspot` repo)
- [ ] Other colleges: the backend already supports several clients
