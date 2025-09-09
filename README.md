# 🏫 오성중학교 동아리 편성 시스템

**창체동아리 신청 및 편성을 위한 웹 기반 관리 시스템**

[![Node.js](https://img.shields.io/badge/Node.js-18.x-green)](https://nodejs.org/)
[![React](https://img.shields.io/badge/React-18.x-blue)](https://reactjs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Latest-blue)](https://postgresql.org/)
[![Express](https://img.shields.io/badge/Express-4.x-yellow)](https://expressjs.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.x-cyan)](https://tailwindcss.com/)

## 📋 목차

- [프로젝트 개요](#-프로젝트-개요)
- [주요 기능](#-주요-기능)
- [기술 스택](#-기술-스택)
- [시스템 아키텍처](#-시스템-아키텍처)
- [설치 및 실행](#-설치-및-실행)
- [배포 가이드](#-배포-가이드)
- [사용 방법](#-사용-방법)
- [API 문서](#-api-문서)
- [데이터베이스 스키마](#-데이터베이스-스키마)
- [보안 고려사항](#-보안-고려사항)
- [문제 해결](#-문제-해결)

## 🎯 프로젝트 개요

오성중학교 학생들의 동아리 신청부터 편성까지 전체 과정을 디지털화한 웹 기반 시스템입니다. 
학생들은 직관적인 인터페이스를 통해 동아리를 탐색하고 신청할 수 있으며, 교사는 효율적으로 편성 과정을 관리할 수 있습니다.

### 🌟 프로젝트 특징

- **💰 완전 무료**: 모든 기술 스택이 오픈소스 또는 무료 서비스 기반
- **📱 반응형 디자인**: 모바일, 태블릿, 데스크톱 모든 기기에서 최적화
- **🔒 보안 강화**: JWT 인증, 입력 검증, SQL 인젝션 방지
- **⚡ 실시간 업데이트**: 동아리 신청 현황 실시간 반영
- **📊 데이터 분석**: 신청 통계 및 배정 결과 시각화

## ✨ 주요 기능

### 👨‍🎓 학생 기능
- **동아리 탐색**: 카테고리별 필터링 및 검색
- **상세 정보 조회**: 동아리별 활동 계획, 목표, 담당교사 정보
- **지망 선택**: 1~3지망까지 우선순위 설정
- **실시간 현황**: 각 동아리 신청자 수 실시간 확인
- **신청 이력 관리**: 개인 신청 현황 및 결과 확인

### 👨‍🏫 교사/관리자 기능
- **신청 현황 모니터링**: 실시간 신청 통계 및 현황 대시보드
- **자동 배정 시스템**: 지망 순위 기반 공정한 자동 배정
- **학생 명단 관리**: 동아리별 배정된 학생 목록 조회
- **데이터 내보내기**: CSV/Excel 형식으로 명단 다운로드
- **통계 분석**: 동아리별 인기도 및 배정 현황 분석

## 🛠 기술 스택

### Frontend
- **React 18**: 사용자 인터페이스 구축
- **Tailwind CSS**: 반응형 디자인 및 스타일링
- **Font Awesome**: 아이콘 시스템
- **Chart.js**: 데이터 시각화

### Backend
- **Node.js**: 서버 런타임 환경
- **Express.js**: 웹 프레임워크
- **PostgreSQL**: 관계형 데이터베이스
- **JWT**: 사용자 인증 및 보안
- **bcryptjs**: 비밀번호 암호화

### DevOps & 배포
- **Render.com**: 무료 클라우드 호스팅
- **GitHub**: 소스 코드 관리
- **PostgreSQL on Render**: 무료 데이터베이스 호스팅

## 🏗 시스템 아키텍처

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Client Side   │    │   Server Side   │    │   Database      │
│                 │    │                 │    │                 │
│ React Frontend  │◄──►│ Express.js API  │◄──►│ PostgreSQL      │
│ Tailwind CSS    │    │ JWT Auth        │    │ Structured Data │
│ Responsive UI   │    │ Security Layer  │    │ Indexed Queries │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### 데이터 플로우
1. **사용자 인증**: JWT 기반 토큰 인증
2. **동아리 데이터**: RESTful API를 통한 CRUD 작업
3. **실시간 업데이트**: 폴링 방식으로 최신 정보 동기화
4. **배정 알고리즘**: 서버 측에서 공정한 배정 로직 실행

## 🚀 설치 및 실행

### 사전 요구사항
- Node.js 18.x 이상
- PostgreSQL 12.x 이상
- Git

### 1. 프로젝트 클론
```bash
git clone https://github.com/your-username/osung-club-system.git
cd osung-club-system
```

### 2. 의존성 설치
```bash
npm install
```

### 3. 환경 변수 설정
```bash
cp .env.example .env
# .env 파일을 편집하여 데이터베이스 연결 정보 입력
```

### 4. 데이터베이스 설정
```bash
# PostgreSQL 데이터베이스 생성
createdb osung_club_db

# 스키마 및 초기 데이터 로드
psql -d osung_club_db -f database/init.sql
psql -d osung_club_db -f database/seed.sql
```

### 5. 서버 실행
```bash
# 개발 모드
npm run dev

# 운영 모드
npm start
```

서버가 실행되면 `http://localhost:3000`에서 접속 가능합니다.

## 🌐 배포 가이드

### Render.com 무료 배포

#### 1. GitHub 저장소 준비
```bash
git add .
git commit -m "Initial commit"
git push origin main
```

#### 2. Render.com 설정
1. [Render.com](https://render.com) 회원가입/로그인
2. "New +" → "PostgreSQL" 선택하여 데이터베이스 생성
3. "New +" → "Web Service" 선택
4. GitHub 저장소 연결
5. 다음 설정 입력:
   - **Name**: `osung-club-system`
   - **Environment**: `Node`
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`

#### 3. 환경 변수 설정
Render.com 대시보드에서 Environment Variables 섹션에 추가:
```
NODE_ENV=production
DATABASE_URL=[Render PostgreSQL URL]
JWT_SECRET=[강력한 랜덤 문자열]
CORS_ORIGIN=https://your-app-name.onrender.com
```

#### 4. 데이터베이스 초기화
```bash
# Render PostgreSQL 연결하여 초기화
psql [DATABASE_URL] -f database/init.sql
psql [DATABASE_URL] -f database/seed.sql
```

## 📚 사용 방법

### 관리자 계정
- **ID**: `admin`
- **비밀번호**: `admin123`

### 학생 테스트 계정
- **ID**: `20251001` (학번)
- **비밀번호**: `student123`

### 기본 워크플로우

1. **관리자**: 시스템 접속 → 동아리 정보 확인
2. **학생**: 로그인 → 동아리 탐색 → 1~3지망 선택 → 신청
3. **관리자**: 신청 현황 확인 → 배정 실행 → 결과 확인
4. **데이터 활용**: CSV 내보내기 → 인쇄 → 배포

## 📡 API 문서

### 인증 API
- `POST /api/login` - 사용자 로그인

### 동아리 API
- `GET /api/clubs` - 동아리 목록 조회
- `GET /api/clubs/:id` - 특정 동아리 상세 정보

### 신청 API
- `POST /api/apply` - 동아리 신청
- `GET /api/my-applications` - 개인 신청 현황

### 관리자 API
- `GET /api/admin/applications` - 전체 신청 현황
- `POST /api/admin/assign-clubs` - 동아리 배정 실행
- `GET /api/admin/assignments` - 배정 결과 조회

## 🗄 데이터베이스 스키마

### 주요 테이블

#### users (사용자)
- `id`: 기본키
- `username`: 로그인 ID
- `password`: 암호화된 비밀번호
- `name`: 실명
- `student_id`: 학번 (학생만)
- `role`: 역할 (student, admin, teacher)

#### clubs (동아리)
- `id`: 기본키
- `name`: 동아리명
- `teacher`: 담당교사
- `category`: 분야
- `location`: 활동 장소
- `max_members`: 최대 정원
- `description`: 동아리 소개

#### applications (신청)
- `id`: 기본키
- `student_id`: 학번 (외래키)
- `club_id`: 동아리 ID (외래키)
- `preference`: 지망 순위 (1, 2, 3)
- `status`: 상태 (pending, assigned, rejected)

## 🔒 보안 고려사항

### 구현된 보안 기능
- **JWT 인증**: 안전한 세션 관리
- **비밀번호 암호화**: bcrypt 해싱
- **SQL 인젝션 방지**: 매개변수화된 쿼리
- **Rate Limiting**: API 남용 방지
- **CORS 정책**: 출처 검증
- **입력 검증**: 클라이언트/서버 양측 검증

### 추가 권장사항
- HTTPS 사용 (Render.com에서 자동 제공)
- 정기적인 백업
- 보안 업데이트 적용
- 접근 로그 모니터링

## 🚨 문제 해결

### 자주 발생하는 문제

#### 1. 데이터베이스 연결 오류
```bash
Error: connect ECONNREFUSED 127.0.0.1:5432
```
**해결책**: PostgreSQL 서비스 시작 및 연결 정보 확인

#### 2. 환경 변수 오류
```bash
Error: JWT_SECRET is not defined
```
**해결책**: `.env` 파일 생성 및 필수 변수 설정

#### 3. 포트 충돌
```bash
Error: listen EADDRINUSE :::3000
```
**해결책**: 다른 포트 사용 또는 실행 중인 프로세스 종료

### 로그 확인
```bash
# 서버 로그 확인
npm run dev

# 데이터베이스 연결 테스트
psql -d osung_club_db -c "SELECT COUNT(*) FROM users;"
```

## 📞 지원 및 기여

### 문의사항
- **개발 관련**: GitHub Issues 활용
- **사용법 문의**: README 문서 참고
- **버그 신고**: 상세한 재현 단계 포함하여 Issues 등록

### 기여 방법
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 라이선스

이 프로젝트는 MIT 라이선스 하에 배포됩니다. 자세한 내용은 `LICENSE` 파일을 참조하세요.

## 🙏 감사의 말

- 오성중학교 교육 공동체
- 오픈소스 커뮤니티
- React, Node.js, PostgreSQL 개발팀
- Render.com 무료 호스팅 서비스

---

**🎓 오성중학교 동아리 편성 시스템**  
*학생들의 꿈과 재능을 키우는 디지털 플랫폼*

**개발**: Claude AI Assistance with K.G.B Technology
**목적**: 교육 혁신 및 디지털 전환 지원  
**버전**: 1.0.0 (2025.09.09)
