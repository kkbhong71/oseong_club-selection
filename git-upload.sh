#!/bin/bash

# 오성중학교 동아리 시스템 GitHub 업로드 스크립트

echo "🚀 오성중학교 동아리 시스템 GitHub 업로드를 시작합니다!"
echo "=============================================="

# 현재 폴더 확인
echo "📁 현재 위치: $(pwd)"
echo ""

# Git 초기화
echo "📝 Git 저장소 초기화 중..."
git init

# 모든 파일 추가
echo "📂 파일 추가 중..."
git add .

# 첫 커밋
echo "💾 첫 번째 커밋 생성 중..."
git commit -m "🎉 오성중학교 동아리 편성 시스템 초기 버전

✨ 주요 기능:
- 학생용 동아리 신청 시스템
- 관리자용 편성 관리 대시보드
- 실시간 신청 현황 확인
- 자동 배정 알고리즘
- CSV 데이터 내보내기
- 반응형 웹 디자인

🛠 기술 스택:
- Frontend: React 18 + Tailwind CSS
- Backend: Node.js + Express.js
- Database: PostgreSQL
- Authentication: JWT
- Deployment: Render.com

🎯 2025학년도 창체동아리 부서 기반 실제 데이터 적용
💰 완전 무료 오픈소스 솔루션"

echo "✅ Git 초기화 완료!"
echo ""

echo "🌐 다음 단계:"
echo "1. GitHub에서 새 저장소 생성 (https://github.com/new)"
echo "2. 저장소 이름: osung-club-system"
echo "3. Public 또는 Private 선택"
echo "4. README, .gitignore, License 추가하지 말고 빈 저장소로 생성"
echo "5. 생성 후 나오는 명령어 실행:"
echo ""
echo "   git remote add origin https://github.com/YOUR-USERNAME/osung-club-system.git"
echo "   git branch -M main"
echo "   git push -u origin main"
echo ""
echo "🚀 업로드 후 Render.com에서 배포 가능!"
echo "📖 상세 가이드: DEPLOY.md 참고"