# MSG-1795: Guarded Bayes Operations

Rspamd's Bayes classifier changes shared detection state. Learning therefore uses stricter access, approval, and monitoring controls than ordinary message scanning.

## Autolearn policy

The effective Bayes classifier includes `config/local.d/bayes_autolearn.conf` from `config/override.d/statistic.conf` and applies these guards:

- Autolearn spam only at a score of **15.0 or higher**. Rspamd 3.10 compares `spam_threshold` inclusively.
- Autolearn ham only at a score of **-2.0 or lower**.
- Require at least **10 tokens** before a message is eligible to learn.
- Retain Rspamd's built-in class-balance guard (`check_balance = true`, `min_balance = 0.9`).
- Do not learn messages containing `CLAM_VIRUS` or `PHISHED_OPENPHISH`. Those deterministic symbols represent policy decisions, not statistical evidence. Explicit unlearn operations remain possible for recovery.

Do not add a second `autolearn` object or an `autolearn = true` setting elsewhere. A duplicate classifier configuration can silently replace these thresholds.

## Manual learning from appeals

The upstream appeals workflow is responsible for all application-level authorization and accounting:

- `learn_ham` tasks require human approval before the MSG-1779 `BayesTaskExecutor` can execute them.
- The upstream rate limit is 10 approved `learn_ham` tasks per account per day.
- Each operation must audit `account_id`, `message_id`, reviewer, and timestamp.
- Learning uses the exact original MIME retained under the MSG-1789 durability contract.

These are defense-in-depth controls: controller authentication does not replace reviewer approval or per-account rate limiting.

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
| `BAYES_STATE_FILE` | `/tmp/rspamd-bayes-health.state` | Previous cumulative sample used to calculate the learn rate |

The first run establishes a learn-rate baseline. Use a persistent `BAYES_STATE_FILE` for a CronJob or monitor that does not retain `/tmp` between runs. The script exits 0 when healthy, 1 on a poisoning alert, and 2 when statistics cannot be authenticated or parsed.

## Verification

The default guard test is offline and exercises configuration assertions plus healthy, high-ratio, high-rate, and malformed-stat monitoring fixtures:

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
- a sudden counter decrease, which can indicate Redis/classifier reset;
- abrupt total-learned growth even when the class ratio remains normal.

An alert is a signal to pause appeal learning, inspect the audited tasks and account distribution, unlearn contaminated MIME samples, and rotate the enable credential if misuse is suspected.
