### Task 4: Docker job in `ci.yml`

**Files:**
- Modify: `.github/workflows/ci.yml` (add `docker` job)
- Uses: `scripts/ci_docker_smoke.sh` from Task 2

**Interfaces:**
- Consumes: `scripts/ci_docker_smoke.sh`; service container env must match script defaults
- Produces: required `docker` job

- [ ] **Step 1: Append docker job to `.github/workflows/ci.yml`**

```yaml
  docker:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17-alpine
        env:
          POSTGRES_USER: analyzer
          POSTGRES_PASSWORD: ci-postgres
          POSTGRES_DB: analyzer
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U analyzer"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
      redis:
        image: redis:8-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli -a ci-redis ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
        env:
          REDIS_PASSWORD: ci-redis
        # redis image needs requirepass via command:
        # override command below
    steps:
      - uses: actions/checkout@v7
      - name: Start Redis with password
        run: |
          # GHA service `command` override — prefer defining redis service as:
          # command: redis-server --requirepass ci-redis
          true
      - name: Docker smoke
        env:
          IMAGE: analyzer-ci:local
          POSTGRES_PASSWORD: ci-postgres
          REDIS_PASSWORD: ci-redis
          ANALYZER_API_KEY: ci-smoke-key
        run: bash scripts/ci_docker_smoke.sh
```

**Use this exact redis service definition** (command with requirepass) — replace the sketch above:

```yaml
      redis:
        image: redis:8-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli -a ci-redis ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
        env:
          REDIS_PASSWORD: ci-redis
```

GitHub Actions `services` support `options` but **not** arbitrary `command` in all cases. Preferred reliable form for Redis password:

```yaml
      redis:
        image: redis:8-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
```

And set smoke script / job env so Redis URL has **no** password if the service has no `--requirepass`, **or** start Redis manually in a step.

**Canonical approach for this plan (choose one and stick to it):**

**Option A (simplest, recommended):** Redis service without password; smoke script uses `redis://127.0.0.1:6379/0` when `REDIS_PASSWORD` is empty.

Update `scripts/ci_docker_smoke.sh` Redis URL construction:

```bash
if [[ -n "${REDIS_PASSWORD}" ]]; then
  REDIS_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/0"
  BROKER_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/1"
  RESULT_URL="redis://:${REDIS_PASSWORD}@127.0.0.1:6379/2"
else
  REDIS_URL="redis://127.0.0.1:6379/0"
  BROKER_URL="redis://127.0.0.1:6379/1"
  RESULT_URL="redis://127.0.0.1:6379/2"
fi
```

In the docker job, export `REDIS_PASSWORD=` (empty) and use unauthenticated Redis service with health `redis-cli ping`.

Final docker job YAML to use:

```yaml
  docker:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:17-alpine
        env:
          POSTGRES_USER: analyzer
          POSTGRES_PASSWORD: ci-postgres
          POSTGRES_DB: analyzer
        ports:
          - 5432:5432
        options: >-
          --health-cmd "pg_isready -U analyzer"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
      redis:
        image: redis:8-alpine
        ports:
          - 6379:6379
        options: >-
          --health-cmd "redis-cli ping"
          --health-interval 5s
          --health-timeout 3s
          --health-retries 10
    steps:
      - uses: actions/checkout@v7
      - uses: docker/setup-buildx-action@v3
      - name: Docker smoke
        env:
          IMAGE: analyzer-ci:local
          POSTGRES_PASSWORD: ci-postgres
          REDIS_PASSWORD: ""
          ANALYZER_API_KEY: ci-smoke-key
        run: bash scripts/ci_docker_smoke.sh
```

Optional: add `docker/build-push-action` with `load: true` and GHA cache instead of raw `docker build` inside the script — YAGNI for v1; keep `docker build` in the script.

- [ ] **Step 2: Align smoke script Redis empty-password branch** (if not done in Task 2)

Edit `scripts/ci_docker_smoke.sh` as shown above; default `REDIS_PASSWORD` to empty string for CI:

```bash
REDIS_PASSWORD="${REDIS_PASSWORD-}"
```

- [ ] **Step 3: Push branch / open draft PR and confirm `docker` job green**

Expected: migrate OK, health returns healthy + database ok within ~60s.

If API cannot reach Postgres via `127.0.0.1` from container: confirm `--network host` is present (Linux GHA only — correct for `ubuntu-latest`).

- [ ] **Step 4: Commit (only if human asks)**

```bash
git add .github/workflows/ci.yml scripts/ci_docker_smoke.sh
git commit -m "$(cat <<'EOF'
ci: add Docker build, migrate, and health smoke job

EOF
)"
```

---
