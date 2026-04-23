# SSAfer CLI MVP

SSAfer CLI는 Docker 기반 프로젝트의 보안 설정 산출물을 수집하는
Windows 우선 CLI 도구입니다.

`.env`, `Dockerfile`, `Containerfile`, Docker Compose YAML 파일 등을
스캔하고, 민감 정보를 마스킹한 로컬 스캔 패키지를 `.ssafer\results`
아래에 생성합니다.

이 MVP는 원본 `.env` 값이나 원본 effective Compose 설정이 업로드되지
않도록 설계되어 있습니다.

## 요구사항

- Windows
- Python 3.10 이상
- Docker Desktop 및 Docker Compose v2
- Trivy, 선택 사항이지만 Dockerfile/config 스캔을 위해 권장

로컬 환경을 확인하려면 다음 명령을 실행합니다.

```powershell
python -m ssafer doctor
```

Trivy가 없다면 다음 명령으로 설치할 수 있습니다.

```powershell
ssafer install-tools
```

## 설치

프로젝트 루트에서 실행합니다.

```powershell
cd C:\Users\SSAFY\Desktop\CLI_TEST
pip install -e .
```

개발 및 테스트용 의존성까지 설치하려면 다음 명령을 사용합니다.

```powershell
pip install -e .[dev]
```

설치 후에는 CLI 명령으로 실행할 수 있습니다.

```powershell
ssafer version
```

또는 Python 모듈로 직접 실행할 수도 있습니다.

```powershell
python -m ssafer version
```

Trivy 같은 외부 실행 파일은 `pip install` 과정에서 자동으로 설치하지 않습니다.
SSAfer 설치 후 다음 명령으로 필요한 선택 도구를 설치할 수 있습니다.

```powershell
ssafer install-tools
```

현재 `install-tools`는 Windows에서 `winget`을 사용해 Trivy를 설치합니다.

## 빠른 시작

1. 로컬 도구 상태를 확인합니다.

```powershell
ssafer doctor
```

2. 대상 프로젝트를 스캔합니다.

```powershell
ssafer run --path .\sample-project
```

3. 마지막 로컬 스캔 결과 요약을 출력합니다.

```powershell
ssafer report --path .\sample-project
```

4. 마지막 스캔 패키지를 백엔드로 업로드합니다.

```powershell
ssafer upload --path .\sample-project
```

기본 업로드 주소는 다음과 같습니다.

```text
http://localhost:8080/api/scans
```

다른 백엔드 주소를 사용하려면 `--api-url` 옵션을 지정합니다.

```powershell
ssafer upload --path .\sample-project --api-url http://localhost:8000
```

## 명령어

### `ssafer version`

현재 CLI 버전을 출력합니다.

```powershell
ssafer version
```

### `ssafer doctor`

SSAfer 실행에 필요한 로컬 도구가 준비되어 있는지 확인합니다.

```powershell
ssafer doctor
```

확인 항목은 다음과 같습니다.

- Python 버전
- Windows 환경 여부
- `trivy.exe`
- Docker
- Docker Compose
- `PATH`에 등록된 Python

Trivy가 설치되어 있지 않으면 `ssafer install-tools`를 안내합니다.

### `ssafer install-tools`

SSAfer가 선택적으로 사용하는 로컬 도구를 설치합니다.

```powershell
ssafer install-tools
```

현재 설치 대상:

- Trivy

Windows에서 내부적으로 실행하는 명령은 다음과 같습니다.

```powershell
winget install --id AquaSecurity.Trivy -e --accept-package-agreements --accept-source-agreements
```

설치 후 현재 터미널에서 `trivy`를 찾지 못하면 터미널을 새로 열고 확인하세요.

```powershell
trivy --version
```

SSAfer는 `trivy`가 `PATH`에 없더라도 winget 기본 설치 경로의 `trivy.exe`를
찾아 사용합니다.

### `ssafer run`

민감 정보가 제거된 로컬 스캔 패키지를 생성합니다.

```powershell
ssafer run --path .\sample-project
```

옵션:

- `--path`, `-p`: 스캔할 프로젝트 루트입니다. 기본값은 현재 디렉터리입니다.
- `--upload`: 스캔 완료 후 생성된 패키지를 업로드합니다.
- `--save-raw`: 원본 effective Compose 설정을 로컬에 저장합니다. 주의해서 사용해야 합니다.
- `--api-url`: `--upload`와 함께 사용할 백엔드 API 기본 URL입니다.

스캔 후 즉시 업로드하는 예시:

```powershell
ssafer run --path .\sample-project --upload --api-url http://localhost:8080
```

원본 effective Compose 출력까지 로컬에 저장하는 예시:

```powershell
ssafer run --path .\sample-project --save-raw
```

일반적인 sanitized workflow에서는 원본 출력이 필요하지 않습니다.
`--save-raw`는 로컬 디버깅이 필요하고, 원본 Compose 출력에 민감 정보가
포함될 수 있음을 이해한 경우에만 사용하세요.

### `ssafer report`

마지막 로컬 스캔 결과 요약을 출력합니다.

```powershell
ssafer report --path .\sample-project
```

아직 스캔 결과가 없다면 다음 메시지와 함께 종료됩니다.

```text
No local scan package found.
```

먼저 `ssafer run`을 실행해 로컬 결과를 생성해야 합니다.

### `ssafer upload`

마지막 로컬 스캔 패키지를 백엔드로 업로드합니다.

```powershell
ssafer upload --path .\sample-project
```

옵션:

- `--path`, `-p`: `.ssafer` 결과가 들어 있는 프로젝트 루트입니다.
- `--api-url`: 백엔드 API 기본 URL입니다. 기본값은 `http://localhost:8080`입니다.

백엔드는 다음 요청을 받을 수 있어야 합니다.

```text
POST /api/scans
```

요청 본문은 `ssafer run`이 생성한 JSON 스캔 패키지입니다.

## 스캔 대상

SSAfer는 대상 프로젝트 루트 아래에서 파일을 재귀적으로 찾습니다.

포함되는 파일 유형:

- `.env`
- `.env.*`
- `Dockerfile`
- `Containerfile`
- `docker-compose.yml`
- `docker-compose.yaml`
- `compose.yml`
- `compose.yaml`
- `docker-compose.*.yml`
- `docker-compose.*.yaml`
- `compose.*.yml`
- `compose.*.yaml`

의존성 디렉터리나 생성 산출물 디렉터리처럼 프로젝트 상수에 설정된 일부
디렉터리는 탐색에서 제외됩니다.

## Compose 처리 방식

SSAfer는 Compose 파일을 스캔 세트로 묶습니다.

대표 예시는 다음과 같습니다.

- `docker-compose.yml`은 `default` 세트를 생성합니다.
- `docker-compose.override.yml`은 `default` 세트에 포함됩니다.
- `docker-compose.dev.yml`은 `dev` 세트를 생성합니다.
- `.env`가 있으면 함께 사용됩니다.
- `.env.dev`가 있으면 `dev` 세트에 함께 사용됩니다.

각 Compose 세트에 대해 SSAfer는 다음 명령을 실행합니다.

```powershell
docker compose -f <compose-file> config
```

생성된 effective Compose 출력은 스캔 패키지에 저장되기 전에 마스킹됩니다.

## 출력 파일

다음 명령을 실행하면:

```powershell
ssafer run --path .\sample-project
```

SSAfer는 아래 경로에 결과를 생성합니다.

```text
.\sample-project\.ssafer
```

주요 경로:

- `.ssafer\results\local-scan-<timestamp>.json`: 전체 스캔 패키지
- `.ssafer\results\last_scan.txt`: 마지막 스캔 패키지를 가리키는 파일
- `.ssafer\effective\sanitized\*.compose.yml`: 마스킹된 effective Compose 파일
- `.ssafer\trivy\*.json`: Trivy 스캔이 성공한 경우 생성되는 JSON 출력
- `.ssafer\effective\raw\*.compose.yml`: `--save-raw` 사용 시에만 생성되는 원본 Compose 출력

스캔 패키지에는 다음 정보가 포함됩니다.

- 스캔 ID
- CLI 버전
- 운영체제
- 도구 버전
- 경고 목록
- 원본 파일 해시
- effective config 해시
- 발견된 대상 파일
- 마스킹된 산출물
- CLI 요약 카운트

## 보안 동작

SSAfer는 일반적인 스캔 출력에 원본 비밀값이 노출되지 않도록 설계되어
있습니다.

현재 보호 동작은 다음과 같습니다.

- `.env` 값은 원본 값이 아니라 메타데이터로 표현됩니다.
- 비어 있지 않은 `.env` 값은 마스킹됩니다.
- Compose environment의 민감 값은 마스킹됩니다.
- URL 안에 포함된 credential은 제거됩니다.
- 원본 effective Compose 출력은 `--save-raw`를 사용하지 않는 한 저장되지 않습니다.

새로운 파일 패턴이나 커스텀 Compose 기능을 사용하는 경우, 외부로 공유하기
전에 생성된 결과물을 직접 확인하는 것을 권장합니다.

## 테스트 실행

개발 의존성을 설치합니다.

```powershell
pip install -e .[dev]
```

전체 테스트를 실행합니다.

```powershell
python -m pytest
```

현재 테스트가 다루는 범위는 다음과 같습니다.

- Compose 세트 생성
- `.env` 메타데이터 마스킹
- Compose YAML sanitization

pytest 캐시 생성을 피하고 임시 디렉터리를 지정하려면 다음 명령을 사용할 수
있습니다.

```powershell
python -m pytest -p no:cacheprovider --basetemp .pytest_tmp
```

예상 결과:

```text
4 passed
```

## 수동 테스트 시나리오

간단한 샘플 프로젝트를 생성합니다.

```powershell
mkdir sample-project
Set-Content sample-project\.env "DB_PASSWORD=super-secret"
Set-Content sample-project\docker-compose.yml @"
services:
  app:
    image: nginx:latest
    environment:
      DB_PASSWORD: super-secret
"@
```

SSAfer를 실행합니다.

```powershell
ssafer run --path .\sample-project
ssafer report --path .\sample-project
```

결과 파일을 확인합니다.

```powershell
Get-ChildItem .\sample-project\.ssafer\results
Get-Content .\sample-project\.ssafer\results\last_scan.txt
```

생성된 JSON에는 `super-secret` 같은 원본 `.env` 값이 포함되지 않아야 합니다.

## 문제 해결

### `No local scan package found.`

`report`와 `upload`는 기존 스캔 결과가 필요합니다. 먼저 다음 명령을
실행하세요.

```powershell
ssafer run --path .\sample-project
```

### `Docker CLI was not found.`

Docker Desktop을 설치하고 실행한 뒤 다음 명령으로 확인합니다.

```powershell
docker --version
docker compose version
```

### `trivy.exe was not found; Dockerfile scan skipped.`

Trivy를 설치합니다.

```powershell
ssafer install-tools
```

설치 후 터미널을 다시 열고 확인합니다.

```powershell
trivy --version
```

`winget list --id AquaSecurity.Trivy -e`에는 표시되지만 `where.exe trivy`에서
찾지 못하는 경우에도 SSAfer는 winget 설치 경로를 직접 탐색합니다.

### 연결 오류로 업로드 실패

백엔드 서버가 실행 중이고 접근 가능한지 확인하세요.

기본 백엔드 URL은 다음과 같습니다.

```text
http://localhost:8080
```

백엔드가 다른 주소에서 실행 중이면 `--api-url`을 사용합니다.

```powershell
ssafer upload --path .\sample-project --api-url http://localhost:8000
```

### HTTP 상태 코드와 함께 업로드 실패

백엔드가 요청을 받았지만 거절한 상태입니다. 백엔드 로그를 확인하고 다음
엔드포인트를 지원하는지 확인하세요.

```text
POST /api/scans
```

## 개발 참고

주요 파일:

- `ssafer\main.py`: CLI 명령과 출력 포맷
- `ssafer\core\result_store.py`: 스캔 흐름 제어 및 결과 저장
- `ssafer\core\finder.py`: 프로젝트 파일 탐색
- `ssafer\core\compose.py`: Compose 세트 생성 및 effective config 렌더링
- `ssafer\core\sanitize.py`: Compose sanitization
- `ssafer\core\env_parser.py`: `.env` 메타데이터 파싱
- `ssafer\core\upload.py`: 백엔드 업로드 클라이언트
- `tests\`: pytest 테스트 스위트
