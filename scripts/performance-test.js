#!/usr/bin/env node

/**
 * 오성중학교 동아리 시스템 - 성능 테스트 스크립트
 * API 응답 시간 및 시스템 성능을 측정합니다
 */

const http = require('http');
const https = require('https');
const { URL } = require('url');

class PerformanceTester {
    constructor(baseUrl = 'http://localhost:3000') {
        this.baseUrl = baseUrl;
        this.results = [];
        this.startTime = Date.now();
    }

    log(message, type = 'info') {
        const timestamp = new Date().toISOString();
        const symbols = {
            info: '📊',
            success: '✅', 
            warning: '⚠️',
            error: '❌',
            test: '🧪'
        };
        console.log(`${symbols[type]} ${timestamp} ${message}`);
    }

    async makeRequest(endpoint, options = {}) {
        return new Promise((resolve, reject) => {
            const url = new URL(endpoint, this.baseUrl);
            const client = url.protocol === 'https:' ? https : http;
            
            const requestOptions = {
                hostname: url.hostname,
                port: url.port,
                path: url.pathname + url.search,
                method: options.method || 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'User-Agent': 'PerformanceTest/1.0',
                    ...options.headers
                },
                timeout: options.timeout || 10000
            };

            const startTime = Date.now();
            const req = client.request(requestOptions, (res) => {
                let data = '';
                
                res.on('data', (chunk) => {
                    data += chunk;
                });
                
                res.on('end', () => {
                    const endTime = Date.now();
                    const responseTime = endTime - startTime;
                    
                    let parsedData = null;
                    try {
                        parsedData = JSON.parse(data);
                    } catch (e) {
                        // HTML 응답 등
                    }
                    
                    resolve({
                        statusCode: res.statusCode,
                        responseTime,
                        dataSize: Buffer.byteLength(data, 'utf8'),
                        data: parsedData,
                        headers: res.headers
                    });
                });
            });

            req.on('error', (error) => {
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Request timeout'));
            });

            if (options.body) {
                req.write(JSON.stringify(options.body));
            }

            req.end();
        });
    }

    async testEndpoint(name, endpoint, options = {}, expectedStatus = 200) {
        this.log(`테스트 중: ${name}`, 'test');
        
        try {
            const result = await this.makeRequest(endpoint, options);
            
            const testResult = {
                name,
                endpoint,
                success: result.statusCode === expectedStatus,
                statusCode: result.statusCode,
                responseTime: result.responseTime,
                dataSize: result.dataSize,
                timestamp: new Date().toISOString()
            };

            if (testResult.success) {
                this.log(`${name}: ${result.responseTime}ms (${this.formatBytes(result.dataSize)})`, 'success');
            } else {
                this.log(`${name}: 실패 - HTTP ${result.statusCode}`, 'error');
            }

            this.results.push(testResult);
            return testResult;
            
        } catch (error) {
            const testResult = {
                name,
                endpoint,
                success: false,
                error: error.message,
                responseTime: null,
                timestamp: new Date().toISOString()
            };
            
            this.log(`${name}: 오류 - ${error.message}`, 'error');
            this.results.push(testResult);
            return testResult;
        }
    }

    async loadTest(endpoint, concurrency = 10, totalRequests = 100) {
        this.log(`부하 테스트 시작: ${endpoint} (동시 연결: ${concurrency}, 총 요청: ${totalRequests})`, 'test');
        
        const startTime = Date.now();
        const results = [];
        const errors = [];
        
        // 배치별로 요청 실행
        const batchSize = concurrency;
        const totalBatches = Math.ceil(totalRequests / batchSize);
        
        for (let batch = 0; batch < totalBatches; batch++) {
            const batchStart = Date.now();
            const promises = [];
            const requestsInBatch = Math.min(batchSize, totalRequests - (batch * batchSize));
            
            // 동시 요청 생성
            for (let i = 0; i < requestsInBatch; i++) {
                promises.push(
                    this.makeRequest(endpoint).then(result => {
                        results.push(result);
                        return result;
                    }).catch(error => {
                        errors.push(error);
                        return { error: error.message, responseTime: null };
                    })
                );
            }
            
            await Promise.all(promises);
            const batchDuration = Date.now() - batchStart;
            
            this.log(`배치 ${batch + 1}/${totalBatches} 완료: ${batchDuration}ms`, 'info');
        }
        
        const totalDuration = Date.now() - startTime;
        const successfulRequests = results.filter(r => r.statusCode && r.statusCode < 400);
        const avgResponseTime = successfulRequests.length > 0 
            ? successfulRequests.reduce((sum, r) => sum + r.responseTime, 0) / successfulRequests.length 
            : 0;
        
        const loadTestResult = {
            endpoint,
            totalRequests,
            successfulRequests: successfulRequests.length,
            failedRequests: errors.length,
            totalDuration,
            averageResponseTime: Math.round(avgResponseTime),
            requestsPerSecond: Math.round((successfulRequests.length / totalDuration) * 1000),
            minResponseTime: successfulRequests.length > 0 ? Math.min(...successfulRequests.map(r => r.responseTime)) : 0,
            maxResponseTime: successfulRequests.length > 0 ? Math.max(...successfulRequests.map(r => r.responseTime)) : 0
        };
        
        this.log(`부하 테스트 완료: ${loadTestResult.successfulRequests}/${totalRequests} 성공, 평균 ${loadTestResult.averageResponseTime}ms`, 'success');
        
        return loadTestResult;
    }

    async runBasicTests() {
        this.log('기본 성능 테스트 시작', 'info');
        this.log('='.repeat(50), 'info');
        
        const tests = [
            // 정적 파일 테스트
            { name: '메인 페이지', endpoint: '/', expectedStatus: 200 },
            
            // API 엔드포인트 테스트
            { name: '헬스체크', endpoint: '/api/health', expectedStatus: 200 },
            { name: '시스템 정보', endpoint: '/api/info', expectedStatus: 200 },
            { name: '동아리 목록', endpoint: '/api/clubs', expectedStatus: 200 },
            
            // 인증 테스트 (실패 예상)
            { name: '인증 필요 API', endpoint: '/api/my-applications', expectedStatus: 401 },
            
            // 404 테스트
            { name: '존재하지 않는 페이지', endpoint: '/nonexistent', expectedStatus: 404 },
            { name: '존재하지 않는 API', endpoint: '/api/nonexistent', expectedStatus: 404 }
        ];
        
        for (const test of tests) {
            await this.testEndpoint(test.name, test.endpoint, {}, test.expectedStatus);
            // 요청 간 간격
            await this.sleep(100);
        }
    }

    async runLoadTests() {
        this.log('부하 테스트 시작', 'info');
        this.log('='.repeat(50), 'info');
        
        const loadTests = [
            { endpoint: '/api/health', concurrency: 5, requests: 50 },
            { endpoint: '/api/clubs', concurrency: 3, requests: 30 },
            { endpoint: '/', concurrency: 10, requests: 100 }
        ];
        
        const loadResults = [];
        
        for (const test of loadTests) {
            const result = await this.loadTest(test.endpoint, test.concurrency, test.requests);
            loadResults.push(result);
            
            // 테스트 간 대기
            await this.sleep(2000);
        }
        
        return loadResults;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    sleep(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    generateReport(loadResults = []) {
        const totalDuration = Date.now() - this.startTime;
        const successful = this.results.filter(r => r.success).length;
        const failed = this.results.filter(r => !r.success).length;
        
        console.log('\n📊 성능 테스트 결과 요약');
        console.log('='.repeat(60));
        console.log(`총 실행 시간: ${totalDuration}ms`);
        console.log(`기본 테스트: ${successful}/${this.results.length} 성공`);
        console.log('');
        
        // 응답 시간 통계
        const responseTimes = this.results
            .filter(r => r.responseTime !== null)
            .map(r => r.responseTime);
            
        if (responseTimes.length > 0) {
            console.log('📈 응답 시간 통계:');
            console.log(`  평균: ${Math.round(responseTimes.reduce((a, b) => a + b) / responseTimes.length)}ms`);
            console.log(`  최소: ${Math.min(...responseTimes)}ms`);
            console.log(`  최대: ${Math.max(...responseTimes)}ms`);
            console.log('');
        }
        
        // 부하 테스트 결과
        if (loadResults.length > 0) {
            console.log('🚀 부하 테스트 결과:');
            loadResults.forEach(result => {
                console.log(`  ${result.endpoint}:`);
                console.log(`    성공률: ${((result.successfulRequests / result.totalRequests) * 100).toFixed(1)}%`);
                console.log(`    평균 응답시간: ${result.averageResponseTime}ms`);
                console.log(`    처리량: ${result.requestsPerSecond} req/s`);
            });
            console.log('');
        }
        
        // 실패한 테스트
        const failures = this.results.filter(r => !r.success);
        if (failures.length > 0) {
            console.log('❌ 실패한 테스트:');
            failures.forEach(failure => {
                console.log(`  ${failure.name}: ${failure.error || `HTTP ${failure.statusCode}`}`);
            });
            console.log('');
        }
        
        // 성능 등급
        const avgResponseTime = responseTimes.length > 0 
            ? responseTimes.reduce((a, b) => a + b) / responseTimes.length 
            : 0;
            
        let grade = 'F';
        if (avgResponseTime < 100) grade = 'A';
        else if (avgResponseTime < 200) grade = 'B';
        else if (avgResponseTime < 500) grade = 'C';
        else if (avgResponseTime < 1000) grade = 'D';
        
        console.log(`🏆 성능 등급: ${grade} (평균 응답시간: ${Math.round(avgResponseTime)}ms)`);
        
        // 권장사항
        console.log('\n💡 권장사항:');
        if (avgResponseTime > 200) {
            console.log('  - API 응답 시간 최적화 필요');
        }
        if (failed > 0) {
            console.log('  - 실패한 엔드포인트 점검 필요');
        }
        if (avgResponseTime < 100) {
            console.log('  - 훌륭한 성능! 현재 상태 유지');
        }
        
        return {
            summary: {
                totalTests: this.results.length,
                successful,
                failed,
                averageResponseTime: Math.round(avgResponseTime),
                grade,
                duration: totalDuration
            },
            details: this.results,
            loadTests: loadResults
        };
    }

    async run() {
        try {
            this.log('🚀 오성중학교 동아리 시스템 성능 테스트 시작', 'info');
            
            // 기본 테스트 실행
            await this.runBasicTests();
            
            // 부하 테스트 실행
            const loadResults = await this.runLoadTests();
            
            // 결과 생성
            const report = this.generateReport(loadResults);
            
            // 성공/실패 판단
            const criticalFailures = this.results.filter(r => 
                !r.success && ['헬스체크', '시스템 정보', '동아리 목록'].includes(r.name)
            ).length;
            
            if (criticalFailures > 0) {
                this.log('💥 중요한 API 실패 감지!', 'error');
                process.exit(1);
            } else if (report.summary.averageResponseTime > 1000) {
                this.log('⚠️ 성능 저하 감지 - 최적화 필요', 'warning');
                process.exit(1);
            } else {
                this.log('✅ 성능 테스트 완료 - 시스템 정상', 'success');
                process.exit(0);
            }
            
        } catch (error) {
            this.log(`성능 테스트 실행 중 오류: ${error.message}`, 'error');
            console.error(error.stack);
            process.exit(1);
        }
    }
}

// 스크립트 실행
if (require.main === module) {
    const baseUrl = process.argv[2] || 'http://localhost:3000';
    const tester = new PerformanceTester(baseUrl);
    
    console.log(`성능 테스트 대상: ${baseUrl}`);
    tester.run();
}

module.exports = PerformanceTester;
