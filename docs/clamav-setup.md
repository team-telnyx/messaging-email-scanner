# ClamAV setup

MSG-1783 adds ClamAV malware scanning to the outbound Rspamd service. Rspamd
connects to `clamd` over TCP, scans MIME parts and message bodies, and emits the
`CLAM_VIRUS` symbol when ClamAV finds malware.

## Local Docker deployment

Build and start the ClamAV service from the repository root:

```bash
docker compose --project-directory . \
  -f docker/docker-compose.clamav.yml up -d --build
docker compose --project-directory . \
  -f docker/docker-compose.clamav.yml ps
```

The named `clamav-db` volume persists downloaded signature databases across
container restarts. The ClamAV image runs `freshclam` to update signatures and
`clamd` listens on TCP port 3310. `clamdping` provides the container health
check.

For a local end-to-end test, place the Rspamd and ClamAV containers on the same
Docker network so that Rspamd can resolve `clamav`. The checked-in
`config/local.d/clamav.conf` connects to `clamav:3310` and
`config/local.d/antivirus.conf` loads that scanner block into Rspamd's built-in
antivirus module. After both services are healthy, run:

```bash
tests/clamav_test.sh
# Or include the EICAR check in the normal canary suite:
RSPAMD_HOST=127.0.0.1 scripts/canary.sh --clamav
```

EICAR is an industry-standard, inert antivirus test string. Do not replace it
with live malware.

## Kubernetes deployment

ClamAV can run as either an Rspamd sidecar or a separately scaled Deployment.

### Sidecar

A sidecar shares the Rspamd pod lifecycle and network namespace. Configure the
Rspamd ClamAV server as `127.0.0.1:3310` instead of `clamav:3310`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: messaging-email-scanner
spec:
  template:
    spec:
      containers:
        - name: rspamd
          image: messaging-email-scanner:<tag>
          ports:
            - name: scanner
              containerPort: 11333
        - name: clamav
          image: <registry>/messaging-email-scanner-clamav:<tag>
          ports:
            - name: clamd
              containerPort: 3310
          readinessProbe:
            exec:
              command: ["clamdping"]
            periodSeconds: 30
            timeoutSeconds: 10
          livenessProbe:
            exec:
              command: ["clamdping"]
            periodSeconds: 30
            timeoutSeconds: 10
          volumeMounts:
            - name: clamav-db
              mountPath: /var/lib/clamav
      volumes:
        - name: clamav-db
          persistentVolumeClaim:
            claimName: clamav-db
```

This model avoids a network hop and keeps one ClamAV instance with each Rspamd
replica, but ClamAV's memory and signature-update overhead is also duplicated
per pod. Use an init/readiness strategy that prevents traffic from reaching
Rspamd until the ClamAV signature database is ready.

### Separate Deployment and Service

A separate Deployment lets ClamAV scale and update independently. Expose only
port 3310 on a cluster-internal Service named `clamav`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: clamav
spec:
  replicas: 2
  selector:
    matchLabels:
      app: clamav
  template:
    metadata:
      labels:
        app: clamav
    spec:
      containers:
        - name: clamav
          image: <registry>/messaging-email-scanner-clamav:<tag>
          ports:
            - name: clamd
              containerPort: 3310
          readinessProbe:
            exec:
              command: ["clamdping"]
            periodSeconds: 30
            timeoutSeconds: 10
          livenessProbe:
            exec:
              command: ["clamdping"]
            periodSeconds: 30
            timeoutSeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: clamav
spec:
  selector:
    app: clamav
  ports:
    - name: clamd
      port: 3310
      targetPort: clamd
```

The checked-in `servers = "clamav:3310"` setting works with this Service. Add a
NetworkPolicy that permits TCP/3310 only from Rspamd pods. Persist or otherwise
cache `/var/lib/clamav` to avoid downloading the full signature database after
every restart.

## Performance and capacity

- ClamAV typically adds about **100–500 ms per message scan**, depending on
  attachment size, archive depth, CPU, storage, and signature cache warmth.
- Budget memory for the loaded signature database and CPU for concurrent MIME
  scans. Measure with production-like attachment distributions before setting
  requests, limits, and replica counts.
- Keep Rspamd's 30-second ClamAV timeout aligned with the upstream KumoMTA scan
  timeout. Monitor timeouts, ClamAV health, signature age, scan latency, and
  queue depth.
- Apply message-size and archive-recursion limits appropriate for the service
  to protect against decompression bombs and pathological attachments.
- Roll signature updates safely and alert when `freshclam` cannot update.

## Deterministic rejection

The Rspamd module uses `action = "add header"`; clean messages receive no
malware symbol. A positive scan emits `CLAM_VIRUS`. MSG-1782 already includes
`CLAM_VIRUS` in the KumoMTA Lua hook's `DETERMINISTIC_SYMBOLS`, so KumoMTA
deterministically rejects malware even when the aggregate Rspamd score is below
the normal score-rejection threshold.
