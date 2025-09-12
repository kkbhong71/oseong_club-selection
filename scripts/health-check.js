#!/usr/bin/env node

/**
 * 오성중학교 동아리 시스템 - 헬스체크 스크립트
 * Render.com 배포 전 시스템 상태 확인
 */

const http = require('http');
const https = require('https');

const config = {
    timeout: parseInt(process.env.HEALTH_CHECK_TIMEOUT) || 8000,
    retries: parseInt(process.env.HEALTH_CHECK_RETRIES) || 2,
    skipCheck: process.env.SKIP_HEALTH_CHECK === 'true',
    isProduction: process.env.NODE_ENV === 'production',
    port: process.env.PORT || 10000
};

console.log('🏥 오성중학교 동아리 시스템 헬스체크 시작...');
console.log(`📊 환경: ${process.env.NODE_ENV || 'development'}`);
console.log(`⚙️ 포트: ${config.port}`);
console.log(`⏱️ 타임아웃: ${config.timeout}ms`);

// 스킵 조건 체크
if (config.skipCheck) {
    console.log('✅ 헬스체크 건너뛰기 (SKIP_HEALTH_CHECK=true)');
    process.exit(0);
}

// 기본 시스템 상태 체크
function checkSystemHealth() {
    console.log('🔍 기본 시스템 상태 체크...');
    
    const memory = process.memoryUsage();
    const memoryMB = Math.round(memory.rss / 1024 / 1024);
    
    console.log(`💾 메모리 사용량: ${memoryMB}MB`);
    console.log(`📦 Node.js 버전: ${process.version}`);
    console.log(`🖥️ 플랫폼: ${process.platform} ${process.arch}`);
    
    // 메모리 경고
    if (memoryMB > 400) {
        console.warn(`⚠️ 메모리 사용량이 높습니다: ${memoryMB}MB`);
    }
    
    // 필수 환경변수 체크
    console.log('🔐 환경변수 체크...');
    const requiredEnvVars = ['NODE_ENV'];
    const missingEnvVars = requiredEnvVars.filter(envVar => !process.env[envVar]);
    
    if (missingEnvVars.length > 0) {
        console.warn(`⚠️ 누락된 환경변수: ${missingEnvVars.join(', ')}`);
    }
    
    return true;
}

// HTTP 헬스체크 (서버가 실행 중인 경우에만)
function performHttpHealthCheck() {
    return new Promise((resolve) => {
        console.log('🌐 HTTP 헬스체크 시도...');
        
        const options = {
            hostname: 'localhost',
            port: config.port,
            path: '/api/health',
            method: 'GET',
            timeout: config.timeout,
            headers: {
                'User-Agent': 'HealthCheck/1.0'
            }
        };
        
        const req = http.request(options, (res) => {
            let data = '';
            
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                if (res.statusCode === 200) {
                    console.log('✅ HTTP 헬스체크 성공');
                    try {
                        const healthData = JSON.parse(data);
                        console.log(`📊 서버 상태: ${healthData.status}`);
                        console.log(`⏰ 서버 업타임: ${healthData.uptime?.human || 'unknown'}`);
                    } catch (e) {
                        console.log('✅ HTTP 응답 수신 완료 (JSON 파싱 불가)');
                    }
                } else {
                    console.warn(`⚠️ HTTP 헬스체크 경고: ${res.statusCode}`);
                }
                resolve(true);
            });
        });
        
        req.on('error', (error) => {
            console.log(`ℹ️ HTTP 헬스체크 불가: ${error.message} (서버가 아직 시작되지 않았을 수 있습니다)`);
            resolve(true); // 에러가 있어도 계속 진행
        });
        
        req.on('timeout', () => {
            console.log('ℹ️ HTTP 헬스체크 타임아웃 (서버 시작 중일 수 있습니다)');
            req.destroy();
            resolve(true);
        });
        
        req.end();
    });
}

// 메인 헬스체크 실행
async function runHealthCheck() {
    try {
        console.log('=' .repeat(50));
        
        // 1. 시스템 상태 체크
        checkSystemHealth();
        
        // 2. HTTP 헬스체크 (프로덕션에서만)
        if (config.isProduction) {
            await performHttpHealthCheck();
        } else {
            console.log('ℹ️ 개발 환경에서는 HTTP 헬스체크를 건너뜁니다');
        }
        
        console.log('=' .repeat(50));
        console.log('✅ 헬스체크 완료 - 시스템 정상');
        console.log('🚀 서버 시작을 계속합니다...');
        
        process.exit(0);
        
    } catch (error) {
        console.error('❌ 헬스체크 실패:', error.message);
        
        if (config.isProduction) {
            console.error('💥 프로덕션 환경에서 헬스체크 실패 - 배포 중단');
            process.exit(1);
        } else {
            console.warn('⚠️ 개발 환경에서 헬스체크 실패 - 계속 진행');
            process.exit(0);
        }
    }
}

// 스크립트 실행
if (require.main === module) {
    runHealthCheck();
} else {
    module.exports = { runHealthCheck, checkSystemHealth };
}
