# MSG-1795: Guarded Bayes Operations

Rspamd's Bayes classifier changes shared detection state. Learning therefore uses stricter access, approval, and monitoring controls than ordinary message scanning.

## Autolearn policy

The effective Bayes classifier includes `config/local.d/bayes_autolearn.conf` from `config/override.d/statistic.conf` and applies these guards:

- Linear's `spam_min = 0.92` and `ham_max = 0.08` acceptance criteria describe high-confidence class gates. Rspamd Bayes autolearn does not consume an external 0..1 probability: it gates on Rspamd's aggregate score. `spam_threshold = 15.0` maps the spam gate to Rspamd's reject threshold (high-confidence spam), while `ham_threshold = -2.0` is the high-confidence ham gate. These are the confidence gates in Rspamd's scoring system, and Rspamd 3.10 compares them inclusively.
- Require at least **10 tokens** before a message is eligible to learn.
- Apply the Linear class-balance gate with `class_balance = 0.9` and retain Rspamd's built-in balance checks (`check_balance = true`, `min_balance = 0.9`).
- Do not learn messages containing `CLAM_VIRUS` or `PHISHED_OPENPHISH`. Those deterministic symbols represent policy decisions, not statistical evidence. Explicit unlearn operations remain possible for recovery.

Do not add a second `autolearn` object or an `autolearn = true` setting elsewhere. A duplicate classifier configuration can silently replace these thresholds.

## Manual learning from appeals

The upstream appeals workflow is responsible for all application-level authorization and accounting:

- `learn_ham` tasks require human approval before the MSG-1779 `BayesTaskExecutor` can execute them.
- The upstream rate limit is 10 approved `learn_ham` tasks per account per day.
- Each operation must audit `account_id`, `message_id`, reviewer, and timestamp.
- Learning uses the exact original MIME retained under the MSG-1789 durability contract.

These are defense-in-depth controls: controller authentication does not replace reviewer approval or per-account rate limiting.

Cross-tenant poisoning enforcement is cross-service scope because the scanner does not own account identity or the appeals audit log. Current and planned controls are:

- **Implemented in MSG-1779:** 10 `learn_ham` operations per account per day and human approval for every learn operation.
- **Future enhancements:** per-tenant contribution caps, learned-message deduplication, and abusive-tenant exclusion.

## Learn API access control

Learning is a privileged controller operation and requires `enable_password`. The container entrypoint hashes credentials supplied through:

- `RSPAMD_CONTROLLER_PASSWORD` for read-only controller operations such as `stat`;
- `RSPAMD_CONTROLLER_ENABLE_PASSWORD` for privileged operations such as `learn_ham` and `learn_spam`.

`config/override.d/worker-controller.inc` sets `secure_ip = []` to remove the packaged loopback password-less default. In Rspamd, non-empty `secure_ip` or `trusted_ips` entries grant password-less access; adding RFC1918 ranges would allow any workload on those networks to bypass learn authentication. Production deployment must expose port 11334 only to KumoMTA, `BayesTaskExecutor`, and authorized monitoring through its Kubernetes Service/NetworkPolicy. The local Compose file publishes the controller on host loopback only.

Never check a plaintext production password into Rspamd configuration. Read and enable credentials should be separate secrets.

## Poisoning monitoring

Run the monitor periodically from a runtime that has `rspamc` and the read-only controller password. For the local Compose service:

```bash
docker compose exec -T rspamd /scripts/bayes_health_check.sh
```

Configuration:

| Variable | Default | Purpose |
| --- | --- | --- |
| `RSPAMD_URL` | `rspamd:11334` | Controller host or `host:port`; an `http://` prefix is accepted and normalized |
| `RSPAMD_PASSWORD` | `RSPAMD_CONTROLLER_PASSWORD` | Read-only controller credential |
| `MAX_HAM_SPAM_RATIO` | `0.5` | Alert when cumulative ham/spam learns exceed this ratio |
| `MAX_LEARNS_PER_HOUR` | `100` | Alert when the sampled learn rate exceeds this value |
| `MAX_CLASS_DISTRIBUTION_DRIFT` | `0.10` | Alert when the current BAYES_SPAM/BAYES_HAM share moves more than this absolute fraction from baseline |
| `MAX_SINGLE_ACCOUNT_SHARE` | `0.20` | Alert when one account contributes more than 20% of audited learns in the query window |
| `BAYES_STATE_FILE` | `/tmp/rspamd-bayes-health.state` | Previous cumulative sample used to calculate the learn rate |
| `BAYES_DISTRIBUTION_BASELINE_FILE` | `${BAYES_STATE_FILE}.distribution-baseline` | Fixed classifier symbol-distribution baseline; the first non-empty run creates it |
| `BAYES_AUDIT_QUERY_CMD` | unset | Trusted command that queries MSG-1779 audit logs and emits `<account_id> <learn_count>` rows |

The first run establishes the learn-rate sample and classifier-distribution baseline. Use persistent state and baseline paths for a CronJob or monitor that does not retain `/tmp` between runs. Replace the distribution baseline only after an approved recalibration; unlike the learn-rate state, it is not updated on every run.

Rspamd statistics do not contain tenant identity. When the MSG-1779 audit-log backend is reachable, configure `BAYES_AUDIT_QUERY_CMD` to aggregate learns by account for the monitoring window. The script alerts if one account contributes more than 20% of all queried learns. Without that query, it emits a notice and continues with global checks. Full per-tenant trend monitoring, contribution-cap enforcement, and abusive-tenant exclusion require cross-service audit-log analysis and remain future enhancements.

The script exits 0 when healthy, 1 on a poisoning alert, and 2 when statistics or a configured audit query cannot be authenticated or parsed.

## Snapshot and rollback

Create a Redis RDB snapshot before classifier-policy changes, bulk seeds, and contaminated-sample cleanup:

```bash
REDIS_URL=redis://redis:6379 \
REDIS_DATA_DIR=/data \
BAYES_SNAPSHOT_DIR=/var/backups/rspamd-bayes \
scripts/bayes_snapshot.sh
```

The script requests a synchronous Redis `SAVE`, copies `/data/dump.rdb` when the Redis data volume is mounted, and otherwise streams an RDB through `redis-cli --rdb`. It retains the 10 newest `bayes-*.rdb` files. Store `BAYES_SNAPSHOT_DIR` on durable, access-controlled storage rather than the default `/tmp`.

Rollback is destructive and requires direct access to the Redis data directory. Pause scanner learning and Redis writers first, then run from the Redis operations container or maintenance pod:

```bash
scripts/bayes_snapshot.sh --restore /var/backups/rspamd-bayes/bayes-20260810T120000Z.rdb
```

Restore flushes the active database, replaces `dump.rdb`, and shuts Redis down without another save so its supervisor can restart it from the selected RDB. For an AOF-enabled deployment, follow the Redis platform runbook to disable or remove the active AOF before restart; otherwise Redis can prefer the AOF over the restored RDB. Verify `rspamc stat` and run `scripts/bayes_health_check.sh` after restart before resuming learns.

## Verification

The default guard test is offline and exercises configuration assertions, snapshot/restore behavior, and healthy, high-ratio, high-rate, class-drift, account-domination, and malformed-stat monitoring fixtures:

```bash
tests/bayes_guard_test.sh
```

With a disposable live controller, opt into the authentication matrix below. It verifies that no password and the read-only password are rejected, while the enable password can perform one real `learn_ham` operation:

```bash
RUN_RSPAMD_INTEGRATION=true \
BAYES_CONTROLLER_URL=http://127.0.0.1:11334 \
BAYES_CONTROLLER_READ_PASSWORD="$RSPAMD_CONTROLLER_PASSWORD" \
BAYES_CONTROLLER_ENABLE_PASSWORD="$RSPAMD_CONTROLLER_ENABLE_PASSWORD" \
tests/bayes_guard_test.sh
```

Investigate:

- a ham/spam ratio above 0.5 (the expected steady-state ratio is below 0.2);
- a learn rate above 100 messages per hour;
- classifier symbol-distribution drift above 0.10 from the approved baseline;
- a single account contributing more than 20% of audited learns;
- a sudden counter decrease, which can indicate Redis/classifier reset;
- abrupt total-learned growth even when the class ratio remains normal.

An alert is a signal to pause appeal learning, inspect the audited tasks and account distribution, unlearn contaminated MIME samples, and rotate the enable credential if misuse is suspected.
