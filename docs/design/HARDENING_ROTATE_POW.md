# Hardening: 빌드별 회전(1) + 경량 PoW(6)

> PR-1: `src/core/hardeningFlags.js` + 단위 테스트만 추가. 빌드/배포 파이프라인에는 아직 연결되지 않음.  
> PR-2: 빌드별 식별자·봉투 필드명 회전.  
> PR-3: 비용 라우트 한정 경량 PoW (enforce 즉시).

## 위협 모델 (요지)

- **자동화·리프트앤시프트**: 정적 분석으로 고정 엔드포인트·봉투 모양을 재사용하는 공격.
- **클라이언트 WASM**은 신뢰하지 않음. 보호는 **Worker + 빌드 산출물**에서 강제.

## (1) 빌드별 회전 — 범위

- **회전 대상**: 내부 `_dokkebi` 식별자, 봉투(요청) 내부 필드명 등 **외부 공개 API 스키마가 아닌 부분**만.
- **비회전**: 사용자 정의 라우트 경로(`/api/...`), JWT 클레임 모양, 공개 JSON 계약.
- **BC 윈도우**: `N = 2` (이전·현재 빌드의 매핑을 동시에 인정). 배포 직후 옛 번들 사용자 보호.
- **롤백**: `DOKKEBI_HARDENING_ROTATE=off` 또는 `DOKKEBI_HARDENING=off`.

## (6) 경량 PoW — 범위

- **부착 대상**: `security.capabilities` 에서 비용 플래그가 있는 라우트, 또는 빌드 시 cost-route 휴리스틱에 걸린 라우트만 (일반 조회 전면 부착 안 함).
- **모드**: 켜면 **바로 enforce** (monitor 단계 없음).
- **난이도**: 보수적 기본값(저사양 기기 체감 지연 목표는 구현 시 튜닝).
- **바인딩**: 서버 nonce + TTL (재사용·녹화 방지는 기존 리플레이/HMAC 라인과 정합).
- **롤백**: `DOKKEBI_HARDENING_POW=off` 또는 `DOKKEBI_HARDENING=off`.

## 환경 변수 (단일 진입점)

| 변수 | 의미 |
|------|------|
| `DOKKEBI_HARDENING=off` | 마스터: rotate·pow 모두 OFF |
| `DOKKEBI_HARDENING_ROTATE=off` | 회전만 OFF (PR-2 연결 후) |
| `DOKKEBI_HARDENING_POW=off` | PoW 만 OFF (PR-3 연결 후) |

unset 시 rotate·pow 는 **ON** (디폴트). 구현: `getHardeningFlags()` (`src/core/hardeningFlags.js`).

## 캐시 / 핸드셰이프

- `index.html`·`/dokkebi/*` 캐시 정책은 기존 `deploy` `_headers` 와 일치 유지.
- 회전 활성화 후에는 **BC 윈도우** 없이 배포하면 클라·서버 불일치로 핸드셰이크 실패가 날 수 있음 → PR-2 에서 BC 반드시 포함.

## 비목표

- 사용자 앱 코드에 수동 패치 요구.
- 외부 공개 REST 스키마의 임의 변경.
