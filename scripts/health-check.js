// scripts/health-check.js
// 시스템 상태를 정기적으로 체크하는 스크립트

const https = require('https');
const http = require('http');

const CONFIG = {
    BASE_URL: process.env.HEALTH_CHECK_URL || 'https://oseong-club-selection.onrender.com',
    TIMEOUT: 10000,
    RETRY_COUNT: 3,
    CRITICAL_ENDPOINTS: [
        '/api/health',
        '/check-database',
        '/'
    ]
};

class HealthChecker {
    constructor() {
        this.results = [];
        this.startTime = Date.now();
    }

    async checkEndpoint(endpoint) {
        const url = `${CONFIG.BASE_URL}${endpoint}`;
        const client = url.startsWith('https') ? https : http;
        
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            const timeout = setTimeout(() => {
                reject(new Error(`Timeout after ${CONFIG.TIMEOUT}ms`));
            }, CONFIG.TIMEOUT);

            const req = client.get(url, (res) => {
                clearTimeout(timeout);
                const duration = Date.now() - startTime;
                
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => {
                    resolve({
                        endpoint,
                        status: res.statusCode,
                        duration,
                        success: res.statusCode < 400,
                        data: this.parseResponse(data),
                        timestamp: new Date().toISOString()
                    });
                });
            });

            req.on('error', (error) => {
                clearTimeout(timeout);
                reject(error);
            });
        });
    }

    parseResponse(data) {
        try {
            return JSON.parse(data);
        } catch {
            return { raw: data.substring(0, 200) };
        }
    }

    async runHealthCheck() {
        console.log('🔍 시스템 헬스체크 시작...');
        console.log(`📡 대상 URL: ${CONFIG.BASE_URL}`);
        console.log('─'.repeat(60));

        for (const endpoint of CONFIG.CRITICAL_ENDPOINTS) {
            let attempts = 0;
            let lastError = null;

            while (attempts < CONFIG.RETRY_COUNT) {
                attempts++;
                
                try {
                    console.log(`📋 ${endpoint} 체크 중... (시도 ${attempts}/${CONFIG.RETRY_COUNT})`);
                    const result = await this.checkEndpoint(endpoint);
                    
                    this.results.push(result);
                    
                    if (result.success) {
                        console.log(`✅ ${endpoint}: OK (${result.duration}ms)`);
                        if (result.data.status || result.data.database_status) {
                            console.log(`   상태: ${result.data.status || result.data.database_status}`);
                        }
                        break;
                    } else {
                        console.log(`⚠️ ${endpoint}: HTTP ${result.status} (${result.duration}ms)`);
                        if (attempts < CONFIG.RETRY_COUNT) {
                            await this.sleep(2000);
                        }
                    }
                } catch (error) {
                    lastError = error;
                    console.log(`❌ ${endpoint}: ${error.message}`);
                    
                    this.results.push({
                        endpoint,
                        success: false,
                        error: error.message,
                        timestamp: new Date().toISOString()
                    });

                    if (attempts < CONFIG.RETRY_COUNT) {
                        console.log(`   ${CONFIG.RETRY_COUNT - attempts}번 더 시도합니다...`);
                        await this.sleep(2000);
                    }
                }
            }
        }

        this.printSummary();
        return this.generateReport();
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    printSummary() {
        console.log('\n' + '='.repeat(60));
        console.log('📊 헬스체크 결과 요약');
        console.log('='.repeat(60));

        const totalDuration = Date.now() - this.startTime;
        const successCount = this.results.filter(r => r.success).length;
        const totalCount = this.results.length;
        const successRate = Math.round((successCount / totalCount) * 100);

        console.log(`⏱️ 총 소요시간: ${totalDuration}ms`);
        console.log(`📈 성공률: ${successCount}/${totalCount} (${successRate}%)`);
        
        if (successRate === 100) {
            console.log('🎉 모든 시스템이 정상 작동 중입니다!');
        } else if (successRate >= 80) {
            console.log('⚠️ 일부 시스템에 경미한 문제가 있습니다.');
        } else {
            console.log('🚨 심각한 시스템 문제가 감지되었습니다!');
        }

        // 개별 결과 출력
        this.results.forEach(result => {
            const status = result.success ? '✅' : '❌';
            const duration = result.duration ? `${result.duration}ms` : 'N/A';
            console.log(`${status} ${result.endpoint}: ${duration}`);
            
            if (!result.success && result.error) {
                console.log(`   오류: ${result.error}`);
            }
        });
    }

    generateReport() {
        const successCount = this.results.filter(r => r.success).length;
        const totalCount = this.results.length;
        
        return {
            timestamp: new Date().toISOString(),
            duration: Date.now() - this.startTime,
            success_rate: Math.round((successCount / totalCount) * 100),
            results: this.results,
            status: successCount === totalCount ? 'healthy' : 
                   successCount >= totalCount * 0.8 ? 'warning' : 'critical',
            recommendations: this.getRecommendations()
        };
    }

    getRecommendations() {
        const recommendations = [];
        const failedEndpoints = this.results.filter(r => !r.success);
        
        if (failedEndpoints.length > 0) {
            recommendations.push('실패한 엔드포인트들을 확인하고 서버 로그를 점검하세요.');
        }

        const slowEndpoints = this.results.filter(r => r.duration && r.duration > 3000);
        if (slowEndpoints.length > 0) {
            recommendations.push('응답시간이 3초 이상인 엔드포인트의 성능을 최적화하세요.');
        }

        if (recommendations.length === 0) {
            recommendations.push('모든 시스템이 정상 작동 중입니다.');
        }

        return recommendations;
    }
}

// 스크립트 실행
async function main() {
    const checker = new HealthChecker();
    
    try {
        const report = await checker.runHealthCheck();
        
        // 결과를 파일로 저장 (선택사항)
        if (process.env.SAVE_REPORT === 'true') {
            const fs = require('fs').promises;
            const filename = `health-report-${Date.now()}.json`;
            await fs.writeFile(filename, JSON.stringify(report, null, 2));
            console.log(`\n📄 상세 보고서가 ${filename}에 저장되었습니다.`);
        }

        // 실패율이 높으면 비정상 종료
        if (report.success_rate < 80) {
            process.exit(1);
        }
        
    } catch (error) {
        console.error('❌ 헬스체크 실행 중 오류:', error.message);
        process.exit(1);
    }
}

// CLI에서 직접 실행될 때만 실행
if (require.main === module) {
    main();
}

module.exports = HealthChecker;
