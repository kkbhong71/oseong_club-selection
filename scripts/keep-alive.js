#!/usr/bin/env node

/**
 * 💤 Render.com Sleep 방지 스크립트
 * 오성중학교 동아리 시스템용
 * 
 * 이 스크립트는 별도의 서버나 GitHub Actions에서 실행하여
 * Render.com 무료 서비스의 Sleep 모드를 방지합니다.
 */

const https = require('https');
const http = require('http');

// 설정
const CONFIG = {
    SERVICE_URL: process.env.SERVICE_URL || 'https://oseong-club-selection.onrender.com',
    KEEP_ALIVE_INTERVAL: parseInt(process.env.KEEP_ALIVE_INTERVAL) || 14 * 60 * 1000, // 14분
    HEALTH_CHECK_TIMEOUT: parseInt(process.env.HEALTH_CHECK_TIMEOUT) || 30000, // 30초
    MAX_RETRIES: parseInt(process.env.MAX_RETRIES) || 3,
    WEBHOOK_URL: process.env.WEBHOOK_URL, // 디스코드/슬랙 웹훅 (선택사항)
    ENABLE_LOGGING: process.env.ENABLE_LOGGING !== 'false'
};

// 로그 유틸리티
const log = {
    info: (...args) => CONFIG.ENABLE_LOGGING && console.log(`[${new Date().toISOString()}] ℹ️`, ...args),
    success: (...args) => CONFIG.ENABLE_LOGGING && console.log(`[${new Date().toISOString()}] ✅`, ...args),
    warn: (...args) => CONFIG.ENABLE_LOGGING && console.warn(`[${new Date().toISOString()}] ⚠️`, ...args),
    error: (...args) => console.error(`[${new Date().toISOString()}] ❌`, ...args)
};

// HTTP 요청 함수
function makeRequest(url, options = {}) {
    return new Promise((resolve, reject) => {
        const protocol = url.startsWith('https:') ? https : http;
        const timeout = setTimeout(() => {
            reject(new Error(`Request timeout after ${CONFIG.HEALTH_CHECK_TIMEOUT}ms`));
        }, CONFIG.HEALTH_CHECK_TIMEOUT);

        const req = protocol.get(url, {
            timeout: CONFIG.HEALTH_CHECK_TIMEOUT,
            headers: {
                'User-Agent': 'Oseong-Club-KeepAlive/1.0'
            },
            ...options
        }, (res) => {
            clearTimeout(timeout);
            
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                resolve({
                    statusCode: res.statusCode,
                    data: data,
                    headers: res.headers
                });
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

// 서비스 상태 확인
async function checkServiceHealth() {
    const startTime = Date.now();
    
    try {
        const response = await makeRequest(`${CONFIG.SERVICE_URL}/api/health`);
        const responseTime = Date.now() - startTime;
        
        if (response.statusCode === 200) {
            let healthData = {};
            try {
                healthData = JSON.parse(response.data);
            } catch (e) {
                // JSON 파싱 실패 시 무시
            }
            
            log.success(`서비스 정상 (${responseTime}ms)`, 
                healthData.status || 'healthy',
                healthData.uptime ? `uptime: ${healthData.uptime.human}` : '');
            
            return {
                success: true,
                responseTime,
                status: healthData.status || 'healthy',
                uptime: healthData.uptime
            };
        } else {
            log.warn(`서비스 응답 비정상: HTTP ${response.statusCode} (${responseTime}ms)`);
            return {
                success: false,
                statusCode: response.statusCode,
                responseTime
            };
        }
    } catch (error) {
        const responseTime = Date.now() - startTime;
        log.error(`서비스 헬스체크 실패 (${responseTime}ms):`, error.message);
        return {
            success: false,
            error: error.message,
            responseTime
        };
    }
}

// Keep-Alive 핑 전송
async function sendKeepAlivePing() {
    const startTime = Date.now();
    
    try {
        const response = await makeRequest(`${CONFIG.SERVICE_URL}/keep-alive`);
        const responseTime = Date.now() - startTime;
        
        if (response.statusCode === 200) {
            log.success(`Keep-Alive 핑 전송 완료 (${responseTime}ms)`);
            return { success: true, responseTime };
        } else {
            log.warn(`Keep-Alive 핑 응답 이상: HTTP ${response.statusCode} (${responseTime}ms)`);
            return { success: false, statusCode: response.statusCode, responseTime };
        }
    } catch (error) {
        const responseTime = Date.now() - startTime;
        log.warn(`Keep-Alive 핑 실패 (${responseTime}ms):`, error.message);
        return { success: false, error: error.message, responseTime };
    }
}

// 서비스 Wake-up 시도
async function wakeUpService() {
    log.info('서비스 Wake-up 시도 중...');
    
    const endpoints = [
        '/api/health',
        '/keep-alive',
        '/api/info'
    ];
    
    for (const endpoint of endpoints) {
        try {
            const response = await makeRequest(`${CONFIG.SERVICE_URL}${endpoint}`);
            if (response.statusCode === 200) {
                log.success(`Wake-up 성공: ${endpoint}`);
                return { success: true, endpoint };
            }
        } catch (error) {
            log.warn(`Wake-up 시도 실패: ${endpoint} -`, error.message);
        }
        
        // 각 시도 사이에 2초 대기
        await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    return { success: false };
}

// 재시도 로직이 있는 Keep-Alive
async function keepAliveWithRetry() {
    let lastError = null;
    
    for (let attempt = 1; attempt <= CONFIG.MAX_RETRIES; attempt++) {
        try {
            // 첫 번째 시도는 헬스체크
            const healthResult = await checkServiceHealth();
            
            if (healthResult.success) {
                // 서비스가 정상이면 추가로 Keep-Alive 핑 전송
                await sendKeepAlivePing();
                return { success: true, attempts: attempt };
            }
            
            // 서비스가 응답하지 않으면 Wake-up 시도
            log.warn(`서비스 응답 없음 (시도 ${attempt}/${CONFIG.MAX_RETRIES}), Wake-up 시도...`);
            const wakeupResult = await wakeUpService();
            
            if (wakeupResult.success) {
                log.success('서비스 Wake-up 완료');
                // Wake-up 후 잠시 대기
                await new Promise(resolve => setTimeout(resolve, 5000));
                
                // 재확인
                const recheckResult = await checkServiceHealth();
                if (recheckResult.success) {
                    return { success: true, attempts: attempt, wokenUp: true };
                }
            }
            
        } catch (error) {
            lastError = error;
            log.error(`Keep-Alive 시도 ${attempt} 실패:`, error.message);
        }
        
        // 마지막 시도가 아니면 대기
        if (attempt < CONFIG.MAX_RETRIES) {
            const delay = attempt * 3000; // 3초, 6초, 9초...
            log.info(`${delay}ms 후 재시도...`);
            await new Promise(resolve => setTimeout(resolve, delay));
        }
    }
    
    return { 
        success: false, 
        attempts: CONFIG.MAX_RETRIES, 
        error: lastError?.message || 'All attempts failed' 
    };
}

// 웹훅 알림 전송 (선택사항)
async function sendWebhookNotification(message, isError = false) {
    if (!CONFIG.WEBHOOK_URL) return;
    
    try {
        const payload = {
            content: `🏫 **오성중학교 동아리 시스템**\n${isError ? '🚨' : '💤'} ${message}`,
            username: 'Keep-Alive Bot'
        };
        
        const postData = JSON.stringify(payload);
        const url = new URL(CONFIG.WEBHOOK_URL);
        
        const options = {
            hostname: url.hostname,
            port: url.port || (url.protocol === 'https:' ? 443 : 80),
            path: url.pathname + url.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            }
        };
        
        const protocol = url.protocol === 'https:' ? https : http;
        const req = protocol.request(options);
        
        req.write(postData);
        req.end();
        
        log.info('웹훅 알림 전송됨');
    } catch (error) {
        log.error('웹훅 알림 전송 실패:', error.message);
    }
}

// 메인 Keep-Alive 루프
async function startKeepAlive() {
    log.info('='.repeat(60));
    log.info('💤 Render.com Sleep 방지 서비스 시작');
    log.info(`📡 서비스 URL: ${CONFIG.SERVICE_URL}`);
    log.info(`⏰ 간격: ${CONFIG.KEEP_ALIVE_INTERVAL / 1000 / 60}분`);
    log.info(`🔄 최대 재시도: ${CONFIG.MAX_RETRIES}회`);
    log.info('='.repeat(60));
    
    let consecutiveFailures = 0;
    let totalRequests = 0;
    let successfulRequests = 0;
    
    // 즉시 첫 번째 체크 실행
    const initialResult = await keepAliveWithRetry();
    totalRequests++;
    
    if (initialResult.success) {
        successfulRequests++;
        log.success('초기 Keep-Alive 성공');
        if (initialResult.wokenUp) {
            await sendWebhookNotification('서비스가 Sleep 모드에서 깨어났습니다.');
        }
    } else {
        consecutiveFailures++;
        log.error('초기 Keep-Alive 실패:', initialResult.error);
        await sendWebhookNotification(`서비스 Keep-Alive 실패: ${initialResult.error}`, true);
    }
    
    // 주기적 실행
    const interval = setInterval(async () => {
        try {
            const result = await keepAliveWithRetry();
            totalRequests++;
            
            if (result.success) {
                successfulRequests++;
                consecutiveFailures = 0;
                
                const successRate = Math.round((successfulRequests / totalRequests) * 100);
                log.success(`Keep-Alive 성공 (성공률: ${successRate}%, 총 ${totalRequests}회)`);
                
                if (result.wokenUp) {
                    await sendWebhookNotification('서비스가 Sleep 모드에서 깨어났습니다.');
                }
            } else {
                consecutiveFailures++;
                log.error(`Keep-Alive 실패 (연속 실패: ${consecutiveFailures}회):`, result.error);
                
                // 연속 3회 실패시 알림
                if (consecutiveFailures === 3) {
                    await sendWebhookNotification(`서비스가 ${consecutiveFailures}회 연속 응답하지 않습니다.`, true);
                }
                
                // 연속 10회 실패시 심각한 문제로 판단
                if (consecutiveFailures >= 10) {
                    log.error('심각한 서비스 장애 감지됨. Keep-Alive 서비스를 중단합니다.');
                    await sendWebhookNotification('심각한 서비스 장애가 감지되어 Keep-Alive를 중단합니다.', true);
                    clearInterval(interval);
                    process.exit(1);
                }
            }
            
        } catch (error) {
            log.error('Keep-Alive 루프 오류:', error);
        }
    }, CONFIG.KEEP_ALIVE_INTERVAL);
    
    // Graceful shutdown
    process.on('SIGTERM', () => {
        log.info('SIGTERM 신호 받음, Keep-Alive 서비스 종료 중...');
        clearInterval(interval);
        process.exit(0);
    });
    
    process.on('SIGINT', () => {
        log.info('SIGINT 신호 받음, Keep-Alive 서비스 종료 중...');
        clearInterval(interval);
        process.exit(0);
    });
    
    log.info('Keep-Alive 서비스가 정상적으로 시작되었습니다.');
}

// CLI 실행 시
if (require.main === module) {
    // 환경 변수 확인
    if (!CONFIG.SERVICE_URL) {
        console.error('❌ SERVICE_URL 환경변수가 필요합니다.');
        process.exit(1);
    }
    
    // Keep-Alive 서비스 시작
    startKeepAlive().catch(error => {
        console.error('❌ Keep-Alive 서비스 시작 실패:', error);
        process.exit(1);
    });
}

module.exports = {
    checkServiceHealth,
    sendKeepAlivePing,
    wakeUpService,
    keepAliveWithRetry,
    startKeepAlive
};
