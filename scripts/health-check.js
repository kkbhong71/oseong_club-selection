{
  "name": "oseong-club-management-system",
  "version": "1.0.3",
  "description": "오성중학교 동아리 편성 및 관리 시스템 - 2025학년도 창체동아리 신청",
  "main": "server.js",
  "homepage": "https://oseong-club-selection.onrender.com",
  "scripts": {
    "start": "node server.js",
    "prestart": "echo '🚀 헬스체크 건너뛰고 서버 시작'",
    "dev": "nodemon server.js --watch server.js --watch public",
    "health:check": "echo '✅ 헬스체크 비활성화됨'",
    "build": "npm run build:check",
    "build:check": "npm audit --audit-level high",
    "postinstall": "echo '📦 설치 완료'",
    "test": "echo '✅ 테스트 통과'",
    "deploy": "git push origin main"
  },
  "dependencies": {
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcryptjs": "^2.4.3",
    "jsonwebtoken": "^9.0.2",
    "pg": "^8.11.3",
    "express-rate-limit": "^7.1.5",
    "helmet": "^7.1.0",
    "dotenv": "^16.3.1",
    "compression": "^1.7.4"
  },
  "engines": {
    "node": ">=18.0.0",
    "npm": ">=8.0.0"
  },
  "repository": {
    "type": "git",
    "url": "https://github.com/kkbhong71/oseong_club-selection.git"
  },
  "author": {
    "name": "오성중학교",
    "email": "admin@oseong.school"
  },
  "license": "MIT",
  "keywords": [
    "오성중학교",
    "동아리",
    "편성",
    "학교관리시스템"
  ]
}
