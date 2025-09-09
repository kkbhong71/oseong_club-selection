# 🚀 오성중학교 동아리 시스템 배포 가이드

## 📋 배포 체크리스트

### ✅ 사전 준비
- [ ] GitHub 계정 생성
- [ ] Render.com 계정 생성 
- [ ] 프로젝트 소스 코드 준비
- [ ] 환경 변수 설정값 준비

---

## 🎯 Render.com 무료 배포 (권장)

### 1단계: GitHub 저장소 생성

```bash
# 프로젝트 폴더에서 실행
git init
git add .
git commit -m "Initial commit: 오성중학교 동아리 시스템"

# GitHub에서 새 저장소 생성 후
git remote add origin https://github.com/your-username/osung-club-system.git
git branch -M main
git push -u origin main
```

### 2단계: Render.com 데이터베이스 생성

1. [Render.com](https://render.com) 로그인
2. **"New +"** → **"PostgreSQL"** 선택
3. 다음 정보 입력:
   - **Name**: `osung-club-db`
   - **Database**: `osung_club_db`
   - **User**: `osung_admin`
   - **Region**: Singapore (가장 가까운 지역)
   - **Plan**: **Free** (1GB 스토리지)
4. **"Create Database"** 클릭
5. 생성된 **Database URL** 복사 (나중에 사용)

### 3단계: Render.com 웹 서비스 생성

1. **"New +"** → **"Web Service"** 선택
2. **"Connect a repository"**에서 GitHub 저장소 연결
3. 다음 설정 입력:

```
Name: osung-club-system
Environment: Node
Region: Singapore
Branch: main
Build Command: npm install
Start Command: npm start
```

### 4단계: 환경 변수 설정

Environment Variables 섹션에서 다음 변수들 추가:

```bash
NODE_ENV=production
DATABASE_URL=[2단계에서 복사한 Database URL]
JWT_SECRET=your-super-secret-jwt-key-2025-osung-middle-school-clubs
BCRYPT_SALT_ROUNDS=10
CORS_ORIGIN=https://your-app-name.onrender.com
MAX_FILE_SIZE=10
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
```

**⚠️ 중요**: JWT_SECRET은 반드시 복잡한 랜덤 문자열로 설정하세요!

### 5단계: 첫 배포 및 데이터베이스 초기화

1. **"Create Web Service"** 클릭
2. 배포 완료 대기 (약 5-10분)
3. 다음 명령어로 데이터베이스 초기화:

```bash
# Render.com Shell에서 실행 또는 로컬에서 원격 DB 연결
npm run db:init
npm run db:seed
```

### 6단계: 배포 확인

1. 생성된 URL 접속 (예: `https://osung-club-system.onrender.com`)
2. 다음 계정으로 로그인 테스트:
   - **관리자**: `admin` / `admin123`
   - **학생**: `20251001` / `student123`

---

## 🔧 다른 배포 옵션

### Heroku (유료 전환됨)
Heroku는 2022년 11월부터 무료 플랜이 종료되어 권장하지 않습니다.

### Railway
Render.com의 대안으로 Railway.app 사용 가능:
1. 계정 생성 후 GitHub 연결
2. PostgreSQL 플러그인 추가
3. 환경 변수 설정 (Render와 동일)

### Vercel + PlanetScale
- Frontend: Vercel (무료)
- Database: PlanetScale (무료 제한)
- 설정이 복잡하지만 성능 우수

---

## 🛠 로컬 개발 환경 설정

### PostgreSQL 설치 (Windows)
```bash
# Chocolatey 사용
choco install postgresql

# 또는 공식 설치 프로그램 다운로드
# https://www.postgresql.org/download/windows/
```

### PostgreSQL 설치 (macOS)
```bash
# Homebrew 사용
brew install postgresql
brew services start postgresql

# 데이터베이스 생성
createdb osung_club_db
```

### PostgreSQL 설치 (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install postgresql postgresql-contrib
sudo systemctl start postgresql
sudo systemctl enable postgresql

# 사용자 및 데이터베이스 생성
sudo -u postgres createuser --interactive
sudo -u postgres createdb osung_club_db
```

### 개발 서버 실행
```bash
# 환경 변수 설정
cp .env.example .env
# .env 파일 편집

# 데이터베이스 초기화
npm run db:reset

# 개발 서버 시작
npm run dev
```

---

## 📊 성능 및 제한사항

### Render.com 무료 플랜 제한
- **CPU**: 0.1 CPU
- **Memory**: 512MB RAM
- **Storage**: 1GB (데이터베이스)
- **Bandwidth**: 100GB/월
- **Sleep**: 15분 비활성화 시 자동 슬립

### 예상 사용량 (150명 학생 기준)
- **데이터 저장**: ~10MB
- **월 트래픽**: ~5GB (여유 있음)
- **동시 접속**: ~20명 (충분함)

### 최적화 팁
1. **이미지 최적화**: 동아리 사진은 WebP 형식 사용
2. **캐싱**: 정적 파일 캐싱 설정
3. **모니터링**: Render 대시보드에서 성능 확인

---

## 🔍 문제 해결

### 배포 실패 시
1. **빌드 로그 확인**: Render 대시보드에서 로그 검토
2. **환경 변수 확인**: 모든 필수 변수 설정 여부
3. **데이터베이스 연결**: DATABASE_URL 올바른지 확인

### 데이터베이스 연결 오류
```bash
# 연결 테스트
psql "your-database-url-here" -c "SELECT version();"

# 스키마 확인
psql "your-database-url-here" -c "\dt"
```

### 슬립 모드 방지 (선택사항)
무료 플랜의 15분 슬립을 방지하려면 외부 모니터링 서비스 사용:
- UptimeRobot (무료)
- Pingdom
- StatusCake

---

## 📈 업그레이드 고려사항

### 유료 플랜 전환 시기
- 학생 수 300명 초과
- 동시 접속자 50명 초과
- 월 트래픽 100GB 초과
- 24/7 가용성 필요

### Render.com 유료 플랜 ($7/월)
- 더 빠른 성능
- 슬립 모드 없음
- 더 많은 리소스
- 우선 지원

---

## 🎉 배포 완료 체크리스트

- [ ] 웹사이트 정상 접속
- [ ] 관리자 로그인 확인  
- [ ] 학생 로그인 확인
- [ ] 동아리 목록 조회
- [ ] 동아리 신청 기능
- [ ] 관리자 대시보드
- [ ] 배정 기능 테스트
- [ ] 데이터 내보내기
- [ ] 모바일 반응형 확인

**🎊 축하합니다! 오성중학교 동아리 시스템이 성공적으로 배포되었습니다!**

---

**문의사항이나 기술 지원이 필요하시면 GitHub Issues를 통해 연락해 주세요.**