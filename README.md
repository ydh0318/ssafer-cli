# SSAfer CLI

Docker 기반 프로젝트의 보안 설정을 수집하는 Windows CLI 도구입니다.

`.env`, `Dockerfile`, Docker Compose 파일을 스캔하고, **민감 정보를 자동으로 마스킹**한 결과물을 로컬에 저장하거나 백엔드로 업로드합니다.

---

## 요구사항

- Windows 10/11
- Python 3.10 이상
- Docker Desktop (Docker Compose v2 포함)
- Trivy (선택사항, Dockerfile 취약점 스캔 시 필요)

---

## 설치

```powershell
pip install git+https://github.com/ydh0318/ssafer-cli.git
```

설치 확인:

```powershell
ssafer version
```

### Trivy 설치 (선택사항)

Dockerfile 취약점 스캔이 필요하다면 Trivy를 함께 설치하세요.

```powershell
ssafer install-tools
```

설치 후 터미널을 새로 열고 확인합니다.

```powershell
trivy --version
```

---

## 빠른 시작

### 1. 환경 점검

```powershell
ssafer doctor
```

Python, Docker, Docker Compose, Trivy 등 필요한 도구가 준비됐는지 확인합니다.

### 2. 스캔 실행

```powershell
ssafer run --path .\my-project
```

### 3. 결과 확인

```powershell
ssafer report --path .\my-project
```

결과 파일 위치, 스캔 대상, 업로드/AI 분석에 들어갈 artifact 목록까지 보려면:

```powershell
ssafer report --path .\my-project --details
```

### 4. 백엔드 업로드 (선택사항)

```powershell
ssafer upload --path .\my-project --api-url http://your-backend:8080
```

---

## 명령어

| 명령어 | 설명 |
|--------|------|
| `ssafer version` | CLI 버전 출력 |
| `ssafer doctor` | 로컬 환경 점검 |
| `ssafer install-tools` | Trivy 자동 설치 (winget) |
| `ssafer run` | 스캔 실행 및 결과 저장 |
| `ssafer report` | 마지막 스캔 결과 요약/상세 출력 |
| `ssafer upload` | 스캔 결과 백엔드 업로드 |

### `ssafer run` 옵션

```powershell
ssafer run --path .\my-project [옵션]
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--path`, `-p` | 스캔할 프로젝트 경로 | 현재 디렉터리 |
| `--upload` | 스캔 후 자동 업로드 | false |
| `--api-url` | 업로드할 백엔드 URL | `http://localhost:8080` |
| `--save-raw` | 원본 Compose 출력 로컬 저장 (주의) | false |

스캔과 업로드를 한 번에:

```powershell
ssafer run --path .\my-project --upload --api-url http://your-backend:8080
```

### `ssafer report` 옵션

```powershell
ssafer report --path .\my-project --details
```

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `--path`, `-p` | 결과를 확인할 프로젝트 경로 | 현재 디렉터리 |
| `--details`, `-d` | 결과 파일, 대상, artifact 목록 출력 | false |

---

## 스캔 대상 파일

SSAfer는 프로젝트 루트를 재귀적으로 탐색해 아래 파일을 수집합니다.

- `.env`, `.env.*`
- `Dockerfile`, `Containerfile`
- `docker-compose.yml / yaml`, `compose.yml / yaml`
- `docker-compose.override.yml`, `compose.override.yml`
- `docker-compose.*.yml`, `compose.*.yml`

`node_modules`, `.git`, `dist`, `build` 등 불필요한 디렉터리는 자동으로 제외됩니다.

---

## 보안 동작

SSAfer는 원본 비밀값이 외부로 유출되지 않도록 설계되어 있습니다.

- `.env` 값은 원본 대신 **해시 + 메타데이터**로 저장
- Compose `environment`의 민감한 값 자동 마스킹 (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY` 등)
- URL에 포함된 인증 정보 제거 (`mysql://user:password@host` → `mysql://user:***MASKED***@host`)
- `--save-raw` 옵션 없이는 원본 Compose 출력이 저장되지 않음

---

## 출력 결과

`ssafer run` 실행 시 프로젝트 내 `.ssafer` 디렉터리에 결과가 저장됩니다.

```
my-project/
└── .ssafer/
    ├── results/
    │   ├── local-scan-<timestamp>.json   # 전체 스캔 패키지
    │   └── last_scan.txt                 # 마지막 스캔 파일 경로
    ├── effective/
    │   └── sanitized/                    # 마스킹된 Compose 파일
    └── trivy/                            # Trivy 스캔 결과 (설치 시)
```

`.ssafer` 디렉터리는 `.gitignore`에 추가하는 것을 권장합니다.

```
# .gitignore
.ssafer/
```

### 보기 좋은 리포트에서 확인할 것

```powershell
ssafer report --path .\my-project --details
```

주요 확인 항목:

- `Status`: `SUCCESS`, `PARTIAL`, `FAILED` 중 하나입니다.
- `Output files`: 생성된 scan package, sanitized Compose, Trivy 결과 경로입니다.
- `Targets`: SSAfer가 발견한 `.env`, Dockerfile, Compose 세트입니다.
- `Artifacts`: 백엔드 업로드와 AI 분석에 들어갈 산출물 목록입니다.
- `Finding count`: Trivy artifact 안의 finding 개수입니다.

정상적으로 생성되어야 하는 artifact 타입:

- `sanitized-effective-compose`: 마스킹된 effective Compose 설정
- `env-metadata`: `.env` 키 목록과 마스킹/해시 메타데이터
- `trivy-json`: Trivy가 생성한 Dockerfile/config 스캔 결과

---

## 문제 해결

### `No local scan package found.`

`report`, `upload` 실행 전에 반드시 스캔을 먼저 해야 합니다.

```powershell
ssafer run --path .\my-project
```

### `Docker CLI was not found.`

Docker Desktop을 설치하고 실행한 후 확인합니다.

```powershell
docker --version
docker compose version
```

### `trivy.exe was not found; Dockerfile scan skipped.`

Trivy가 없으면 Dockerfile 스캔이 건너뜁니다. 설치하려면:

```powershell
ssafer install-tools
```

설치 후 터미널을 새로 열고 재시도하세요.

### 업로드 실패 (연결 오류)

백엔드 서버가 실행 중인지 확인하고, `--api-url`로 정확한 주소를 지정하세요.

```powershell
ssafer upload --path .\my-project --api-url http://your-backend:8080
```

백엔드는 `POST /api/scans` 엔드포인트를 지원해야 합니다.

---

## 개발자 참고

```powershell
# 소스에서 설치 (개발 모드)
git clone https://github.com/ydh0318/ssafer-cli.git
cd ssafer-cli
pip install -e .[dev]

# 테스트 실행
python -m pytest
```

주요 모듈:

- `ssafer/main.py` — CLI 명령어 정의
- `ssafer/core/result_store.py` — 스캔 흐름 제어
- `ssafer/core/sanitize.py` — 민감정보 마스킹
- `ssafer/core/compose.py` — Compose 세트 구성
- `ssafer/core/finder.py` — 파일 탐색
- `ssafer/core/trivy.py` — Trivy 통합
