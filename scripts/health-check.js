#!/usr/bin/env node

/**
 * 🏥 오성중학교 동아리 시스템 - 헬스체크 스크립트
 * Render.com 배포 환경 최적화 버전
 * 
 * 이 스크립트는 서버 시작 전/후 시스템 상태를 확인합니다
 * Render.com의 Sleep 모드 문제 해결을 위한 최적화 포함
 */

const http = require('http');
const https = require('https');
const { performance } = require('perf_hooks');

// 환경 설정
const CONFIG = {
    NODE_ENV: process.env.NODE_ENV || 'development',
    PORT: process.env.PORT || 10000,
    HEALTH_CHECK_TIMEOUT: parseInt(process.env.HEALTH_CHECK_TIMEOUT) || 8000,
    HEALTH_CHECK_RETRIES: parseInt(process.env.HEALTH_CHECK_RETRIES) || 2,
    SKIP_HEALTH_CHECK: process.env.SKIP_HEALTH_CHECK === 'true',
    RENDER_SERVICE_URL: process.env.RENDER_EXTERNAL_URL || 'https://oseong-club-selection.onrender.com',
    DATABASE_URL: process.env.DATABASE_URL,
    INIT_KEY: process.env.INIT_KEY || 'InitKey2025!@#'
};

// 로그 유틸리티
const log = {
    info: (...args) => console.log('ℹ️', new Date().toISOString(), ...args),
    success: (...args) => console.log('✅', new Date().toISOString(), ...args),
    warn: (...args) => console.warn('⚠️', new Date().toISOString(), ...args),
    error: (...args) => console.error('❌', new Date().toISOString(), ...args),
    debug: (...args) => {
        if (CONFIG.NODE_ENV === 'development') {
            console.log('🐛', new Date().toISOString(), ...args);
        }
    }
};

// HTTP 요청 유틸리티
function makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            reject(new Error(`Request timeout after ${CONFIG.HEALTH_CHECK_TIMEOUT}ms`));
        }, CONFIG.HEALTH_CHECK_TIMEOUT);

        const protocol = url.startsWith('https:') ? https : http;
        
        const req = protocol.get(url, {
            timeout: CONFIG.HEALTH_CHECK_TIMEOUT,
            ...options
        }, (res) => {
            clearTimeout(timeout);
            
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    const jsonData = data ? JSON.parse(data) : {};
                    resolve({
                        statusCode: res.statusCode,
                        data: jsonData,
                        headers: res.headers
                    });
                } catch (error) {
                    resolve({
                        statusCode: res.statusCode,
                        data: data,
                        headers: res.headers
                    });
                }
            });
        });

        req.on('error', (error) => {
            clearTimeout(timeout);
            reject(error);
        });

        req.on('timeout', () => {
            clearTimeout(timeout);
            req.destroy();
            reject(new Error('Request timeout'));
        });
    });
}

// 시스템 리소스 체크
function checkSystemResources() {
    const memoryUsage = process.memoryUsage();
    const cpuUsage = process.cpuUsage();
    
    return {
        memory: {
            rss_mb: Math.round(memoryUsage.rss / 1024 / 1024),
            heap_used_mb: Math.round(memoryUsage.heapUsed / 1024 / 1024),
            heap_total_mb: Math.round(memoryUsage.heapTotal / 1024 / 1024),
            external_mb: Math.round(memoryUsage.external / 1024 / 1024)
        },
        cpu: {
            user: cpuUsage.user,
            system: cpuUsage.system
        },
        uptime_seconds: Math.floor(process.uptime()),
        node_version: process.version,
        platform: process.platform,
        arch: process.arch
    };
}

// 환경변수 검증
function validateEnvironment() {
    const required = [
        'DATABASE_URL'
    ];
    
    const missing = required.filter(key => !process.env[key]);
    
    if (missing.length > 0) {
        log.error('필수 환경변수가 누락되었습니다:', missing);
        return false;
    }
    
    log.success('환경변수 검증 통과');
    return true;
}

// 로컬 서버 헬스체크
async function checkLocalHealth() {
    const startTime = performance.now();
    
    try {
        const response = await makeRequest(`http://localhost:${CONFIG.PORT}/api/health`);
        const duration = Math.round(performance.now() - startTime);
        
        if (response.statusCode === 200) {
            log.success(`로컬 헬스체크 성공 (${duration}ms)`, response.data.status);
            return { success: true, duration, data: response.data };
        } else {
            log.warn(`로컬 헬스체크 실패 (${response.statusCode})`, response.data);
            return { success: false, statusCode: response.statusCode, data: response.data };
        }
    } catch (error) {
        const duration = Math.round(performance.now() - startTime);
        log.error(`로컬 헬스체크 에러 (${duration}ms):`, error.message);
        return { success: false, error: error.message, duration };
    }
}

// 데이터베이스 상태 확인
async function checkDatabaseStatus() {
    const startTime = performance.now();
    
    try {
        const response = await makeRequest(`http://localhost:${CONFIG.PORT}/check-database`);
        const duration = Math.round(performance.now() - startTime);
        
        if (response.statusCode === 200) {
            const status = response.data.database_status;
            
            if (status === 'ready') {
                log.success(`데이터베이스 준비 완료 (${duration}ms)`);
                return { success: true, status: 'ready', duration };
            } else {
                log.warn(`데이터베이스 초기화 필요 (${duration}ms)`);
                return { 
                    success: false, 
                    status: 'needs_initialization', 
                    init_url: response.data.init_url,
                    duration 
                };
            }
        } else {
            log.error(`데이터베이스 상태 확인 실패 (${response.statusCode})`);
            return { success: false, statusCode: response.statusCode };
        }
    } catch (error) {
        const duration = Math.round(performance.now() - startTime);
        log.error(`데이터베이스 상태 확인 에러 (${duration}ms):`, error.message);
        return { success: false, error: error.message, duration };
    }
}

// 데이터베이스 초기화
async function initializeDatabase() {
    log.info('데이터베이스 초기화 중...');
    const startTime = performance.now();
    
    try {
        const response = await makeRequest(
            `http://localhost:${CONFIG.PORT}/init-database?key=${CONFIG.INIT_KEY}`
        );
        const duration = Math.round(performance.now() - startTime);
        
        if (response.statusCode === 200) {
            log.success(`데이터베이스 초기화 완료 (${duration}ms)`);
            return { success: true, duration, data: response.data };
        } else {
            log.error(`데이터베이스 초기화 실패 (${response.statusCode})`);
            return { success: false, statusCode: response.statusCode };
        }
    } catch (error) {
        const duration = Math.round(performance.now() - startTime);
        log.error(`데이터베이스 초기화 에러 (${duration}ms):`, error.message);
        return { success: false, error: error.message, duration };
    }
}

// 원격 Wake-up 요청 (Render Sleep 모드 해제)
async function wakeupService() {
    if (CONFIG.NODE_ENV !== 'production') {
        log.debug('개발 모드에서는 Wake-up 요청을 건너뜁니다');
        return { success: true, skipped: true };
    }
    
    log.info('서비스 Wake-up 중...');
    const startTime = performance.now();
    
    try {
        const response = await makeRequest(CONFIG.RENDER_SERVICE_URL + '/api/health');
        const duration = Math.round(performance.now() - startTime);
        
        if (response.statusCode === 200) {
            log.success(`서비스 Wake-up 완료 (${duration}ms)`);
            return { success: true, duration };
        } else {
            log.warn(`서비스 Wake-up 실패 (${response.statusCode}) - ${duration}ms`);
            return { success: false, statusCode: response.statusCode, duration };
        }
    } catch (error) {
        const duration = Math.round(performance.now() - startTime);
        log.warn(`서비스 Wake-up 에러 (${duration}ms):`, error.message);
        return { success: false, error: error.message, duration };
    }
}

// 재시도 로직이 있는 헬스체크
async function checkHealthWithRetry() {
    for (let attempt = 1; attempt <= CONFIG.HEALTH_CHECK_RETRIES; attempt++) {
        log.info(`헬스체크 시도 ${attempt}/${CONFIG.HEALTH_CHECK_RETRIES}`);
        
        const result = await checkLocalHealth();
        
        if (result.success) {
            return result;
        }
        
        if (attempt < CONFIG.HEALTH_CHECK_RETRIES) {
            const delay = attempt * 1000; // 1초, 2초, 3초...
            log.info(`${delay}ms 후 재시도...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    
    return { success: false, error: 'All retry attempts failed' };
}

// 메인 헬스체크 함수
async function performHealthCheck() {
    const overallStartTime = performance.now();
    log.info('='.repeat(60));
    log.info(`🏥 오성중학교 동아리 시스템 헬스체크 시작`);
    log.info(`환경: ${CONFIG.NODE_ENV} | 포트: ${CONFIG.PORT}`);
    log.info('='.repeat(60));

    // Skip 체크
    if (CONFIG.SKIP_HEALTH_CHECK) {
        log.warn('헬스체크가 건너뛰어집니다 (SKIP_HEALTH_CHECK=true)');
        return 0;
    }

    const results = {
        environment: null,
        system: null,
        wakeup: null,
        local_health: null,
        database: null,
        database_init: null
    };

    try {
        // 1. 환경변수 검증
        log.info('1️⃣ 환경변수 검증 중...');
        results.environment = validateEnvironment();
        if (!results.environment) {
            throw new Error('환경변수 검증 실패');
        }

        // 2. 시스템 리소스 확인
        log.info('2️⃣ 시스템 리소스 확인 중...');
        results.system = checkSystemResources();
        log.info(`메모리 사용량: ${results.system.memory.rss_mb}MB`);
        log.info(`힙 사용량: ${results.system.memory.heap_used_mb}MB`);

        // 3. Wake-up 서비스 (Production only)
        log.info('3️⃣ 서비스 Wake-up 확인 중...');
        results.wakeup = await wakeupService();

        // 4. 로컬 헬스체크
        log.info('4️⃣ 로컬 서비스 헬스체크 중...');
        results.local_health = await checkHealthWithRetry();
        
        if (!results.local_health.success) {
            log.warn('로컬 헬스체크 실패 - 서버가 아직 시작되지 않았을 수 있습니다');
        }

        // 5. 데이터베이스 상태 확인
        if (results.local_health.success) {
            log.info('5️⃣ 데이터베이스 상태 확인 중...');
            results.database = await checkDatabaseStatus();
            
            // 6. 필요시 데이터베이스 초기화
            if (!results.database.success && results.database.status === 'needs_initialization') {
                log.info('6️⃣ 데이터베이스 초기화 실행 중...');
                results.database_init = await initializeDatabase();
                
                if (results.database_init.success) {
                    // 초기화 후 상태 재확인
                    results.database = await checkDatabaseStatus();
                }
            }
        }

        // 결과 종합
        const overallDuration = Math.round(performance.now() - overallStartTime);
        log.info('='.repeat(60));
        log.info('📊 헬스체크 결과 요약:');
        log.info(`   환경변수: ${results.environment ? '✅' : '❌'}`);
        log.info(`   시스템: ✅ (${results.system.memory.rss_mb}MB 사용중)`);
        log.info(`   Wake-up: ${results.wakeup.success || results.wakeup.skipped ? '✅' : '⚠️'}`);
        log.info(`   로컬 서비스: ${results.local_health.success ? '✅' : '⚠️'}`);
        log.info(`   데이터베이스: ${results.database?.success ? '✅' : '⚠️'}`);
        if (results.database_init) {
            log.info(`   DB 초기화: ${results.database_init.success ? '✅' : '❌'}`);
        }
        log.info(`   전체 소요시간: ${overallDuration}ms`);
        log.info('='.repeat(60));

        // 최종 상태 결정
        const critical_failures = [
            !results.environment,
            results.database_init?.success === false
        ].filter(Boolean);

        if (critical_failures.length > 0) {
            log.error('치명적인 오류가 발생했습니다');
            return 1;
        }

        const warnings = [
            !results.local_health.success,
            !results.database?.success,
            !results.wakeup.success && !results.wakeup.skipped
        ].filter(Boolean);

        if (warnings.length > 0) {
            log.warn(`${warnings.length}개의 경고가 있지만 진행합니다`);
        } else {
            log.success('모든 헬스체크가 성공했습니다! 🎉');
        }

        return 0;

    } catch (error) {
        const overallDuration = Math.round(performance.now() - overallStartTime);
        log.error('='.repeat(60));
        log.error('💥 헬스체크 중 오류 발생:');
        log.error(`   오류: ${error.message}`);
        log.error(`   소요시간: ${overallDuration}ms`);
        log.error('='.repeat(60));
        return 1;
    }
}

// CLI 실행
if (require.main === module) {
    performHealthCheck()
        .then(exitCode => {
            if (exitCode === 0) {
                log.success('헬스체크 완료');
            } else {
                log.error('헬스체크 실패');
            }
            process.exit(exitCode);
        })
        .catch(error => {
            log.error('헬스체크 스크립트 실행 오류:', error);
            process.exit(1);
        });
}

module.exports = {
    performHealthCheck,
    checkLocalHealth,
    checkDatabaseStatus,
    initializeDatabase,
    wakeupService,
    validateEnvironment
};
