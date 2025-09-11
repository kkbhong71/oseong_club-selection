#!/bin/bash

# deploy.sh - 오성중학교 동아리 시스템 자동 배포 스크립트
# 사용법: ./deploy.sh [production|staging|development]

set -e  # 에러 발생 시 스크립트 중단

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 로깅 함수
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 환경 설정
ENVIRONMENT=${1:-production}
PROJECT_NAME="oseong-club-selection"
BACKUP_DIR="./deployment-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

log_info "🚀 오성중학교 동아리 시스템 배포 시작"
log_info "환경: $ENVIRONMENT"
log_info "시간: $(date)"

# 필수 파일 존재 확인
check_required_files() {
    log_info "📋 필수 파일 존재 확인..."
    
    local required_files=(
        "server.js"
        "public/index.html"
        "package.json"
        ".env.example"
    )
    
    for file in "${required_files[@]}"; do
        if [[ ! -f "$file" ]]; then
            log_error "필수 파일이 없습니다: $file"
            exit 1
        fi
    done
    
    log_success "모든 필수 파일 확인 완료"
}

# 환경변수 검증
validate_environment() {
    log_info "🔍 환경변수 검증..."
    
    # .env 파일이 있는지 확인
    if [[ ! -f ".env" ]]; then
        log_warning ".env 파일이 없습니다. .env.example을 참고하여 생성하세요."
        
        if [[ "$ENVIRONMENT" == "production" ]]; then
            log_error "프로덕션 환경에서는 .env 파일이 필수입니다"
            exit 1
        fi
    fi
    
    # 필수 환경변수 확인
    local required_vars=(
        "DATABASE_URL"
        "JWT_SECRET"
        "ADMIN_PASSWORD"
    )
    
    for var in "${required_vars[@]}"; do
        if [[ -z "${!var}" ]] && [[ -f ".env" ]]; then
            if ! grep -q "^$var=" .env; then
                log_warning "환경변수 $var가 설정되지 않았습니다"
            fi
        fi
    done
    
    log_success "환경변수 검증 완료"
}

# 의존성 설치
install_dependencies() {
    log_info "📦 의존성 설치..."
    
    if [[ ! -f "package-lock.json" ]]; then
        log_info "package-lock.json이 없습니다. 새로 생성합니다."
    fi
    
    npm ci --production
    
    if [[ $? -eq 0 ]]; then
        log_success "의존성 설치 완료"
    else
        log_error "의존성 설치 실패"
        exit 1
    fi
}

# 데이터베이스 상태 확인
check_database() {
    log_info "🗄️ 데이터베이스 연결 확인..."
    
    # Node.js를 사용한 데이터베이스 연결 테스트
    node -e "
        const { Pool } = require('pg');
        const pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        pool.query('SELECT NOW()')
            .then(() => {
                console.log('✅ 데이터베이스 연결 성공');
                process.exit(0);
            })
            .catch(err => {
                console.error('❌ 데이터베이스 연결 실패:', err.message);
                process.exit(1);
            })
            .finally(() => pool.end());
    "
    
    if [[ $? -eq 0 ]]; then
        log_success "데이터베이스 연결 확인 완료"
    else
        log_error "데이터베이스 연결 실패"
        exit 1
    fi
}

# 백업 생성
create_backup() {
    log_info "💾 배포 전 백업 생성..."
    
    mkdir -p "$BACKUP_DIR"
    
    # 현재 상태 백업
    local backup_file="$BACKUP_DIR/backup_${TIMESTAMP}.tar.gz"
    
    tar -czf "$backup_file" \
        --exclude=node_modules \
        --exclude=.git \
        --exclude="$BACKUP_DIR" \
        --exclude=logs \
        .
    
    log_success "백업 생성 완료: $backup_file"
    
    # 데이터베이스 백업 (가능한 경우)
    if command -v node >/dev/null 2>&1; then
        log_info "데이터베이스 백업 생성 중..."
        node scripts/backup-system.js create 2>/dev/null || log_warning "데이터베이스 백업 건너뜀"
    fi
}

# 보안 검사
security_check() {
    log_info "🔒 보안 검사 실행..."
    
    # 기본 비밀번호 확인
    if [[ "$ADMIN_PASSWORD" == "admin123" ]]; then
        log_error "기본 관리자 비밀번호를 변경해야 합니다!"
        exit 1
    fi
    
    # JWT 시크릿 강도 확인
    if [[ ${#JWT_SECRET} -lt 32 ]]; then
        log_warning "JWT_SECRET이 너무 짧습니다. 32자 이상 권장"
    fi
    
    # NODE_ENV 확인
    if [[ "$ENVIRONMENT" == "production" && "$NODE_ENV" != "production" ]]; then
        log_warning "NODE_ENV가 production으로 설정되지 않았습니다"
    fi
    
    log_success "보안 검사 완료"
}

# 애플리케이션 테스트
test_application() {
    log_info "🧪 애플리케이션 테스트..."
    
    # 서버 시작 (백그라운드)
    node server.js &
    SERVER_PID=$!
    
    # 서버 시작 대기
    sleep 5
    
    # 헬스체크
    local health_url="http://localhost:${PORT:-3000}/api/health"
    
    if curl -s "$health_url" | grep -q '"status":"healthy"'; then
        log_success "헬스체크 통과"
    else
        log_error "헬스체크 실패"
        kill $SERVER_PID 2>/dev/null
        exit 1
    fi
    
    # 서버 종료
    kill $SERVER_PID 2>/dev/null
    sleep 2
    
    log_success "애플리케이션 테스트 완료"
}

# Git 커밋 및 푸시 (선택사항)
git_deploy() {
    if [[ "$ENVIRONMENT" == "production" ]] && git status >/dev/null 2>&1; then
        log_info "📤 Git 커밋 및 푸시..."
        
        # 변경사항이 있는지 확인
        if ! git diff-index --quiet HEAD --; then
            log_info "변경사항 감지, 커밋 중..."
            
            git add .
            git commit -m "Deploy: $TIMESTAMP - All issues fixed and optimized"
            
            # 원격 저장소에 푸시
            if git remote | grep -q origin; then
                git push origin main || git push origin master
                log_success "Git 푸시 완료"
            else
                log_warning "Git 원격 저장소가 설정되지 않음"
            fi
        else
            log_info "커밋할 변경사항이 없습니다"
        fi
    fi
}

# Render 배포 상태 확인 (선택사항)
check_render_status() {
    if [[ "$ENVIRONMENT" == "production" ]]; then
        log_info "🌐 Render 배포 상태 확인..."
        
        local app_url="https://oseong-club-selection.onrender.com"
        
        # 30초 대기 후 상태 확인
        log_info "배포 완료 대기 중... (30초)"
        sleep 30
        
        if curl -s "$app_url/api/health" | grep -q '"status":"healthy"'; then
            log_success "Render 배포 성공 확인"
            log_success "애플리케이션 URL: $app_url"
        else
            log_warning "Render 배포 상태를 확인할 수 없습니다"
            log_info "수동으로 확인해주세요: $app_url"
        fi
    fi
}

# 배포 후 정리
cleanup() {
    log_info "🧹 배포 후 정리..."
    
    # 오래된 백업 정리 (7일 이상)
    find "$BACKUP_DIR" -name "backup_*.tar.gz" -mtime +7 -delete 2>/dev/null || true
    
    # 임시 파일 정리
    rm -rf /tmp/oseong-* 2>/dev/null || true
    
    log_success "정리 완료"
}

# 배포 완료 알림
deployment_summary() {
    echo ""
    echo "========================================"
    echo "🎉 배포 완료!"
    echo "========================================"
    echo "환경: $ENVIRONMENT"
    echo "시간: $(date)"
    echo "백업: $BACKUP_DIR/backup_${TIMESTAMP}.tar.gz"
    
    if [[ "$ENVIRONMENT" == "production" ]]; then
        echo "URL: https://oseong-club-selection.onrender.com"
        echo ""
        echo "📋 배포 후 확인사항:"
        echo "1. 관리자 로그인 테스트 (admin / 설정한비밀번호)"
        echo "2. 학생 가입 및 로그인 테스트"
        echo "3. 동아리 신청 플로우 테스트"
        echo "4. 헬스체크 확인: /api/health"
        echo "5. 데이터베이스 상태 확인: /check-database"
    fi
    
    echo ""
    echo "🔧 문제 발생 시:"
    echo "1. 로그 확인: Render 대시보드"
    echo "2. 백업 복원: tar -xzf $BACKUP_DIR/backup_${TIMESTAMP}.tar.gz"
    echo "3. 헬스체크 스크립트: node scripts/health-check.js"
    echo ""
}

# 에러 핸들링
trap 'log_error "배포 중 오류 발생. 백업에서 복원을 고려하세요."; exit 1' ERR

# 메인 배포 프로세스
main() {
    case $ENVIRONMENT in
        production|staging|development)
            log_info "배포 환경: $ENVIRONMENT"
            ;;
        *)
            log_error "유효하지 않은 환경: $ENVIRONMENT"
            log_info "사용법: ./deploy.sh [production|staging|development]"
            exit 1
            ;;
    esac
    
    # 배포 단계별 실행
    check_required_files
    validate_environment
    create_backup
    install_dependencies
    check_database
    security_check
    
    if [[ "$ENVIRONMENT" != "production" ]]; then
        test_application
    fi
    
    git_deploy
    
    if [[ "$ENVIRONMENT" == "production" ]]; then
        check_render_status
    fi
    
    cleanup
    deployment_summary
}

# 스크립트 실행
main "$@"

# 배포 성공
log_success "🎉 모든 배포 과정이 성공적으로 완료되었습니다!"
exit 0
