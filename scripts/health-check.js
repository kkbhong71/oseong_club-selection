#!/usr/bin/env node

/**
 * 오성중학교 동아리 시스템 - 헬스체크 스크립트
 * 서버 시작 전 시스템 상태를 검사합니다
 */

const http = require('http');
const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');

// 환경 변수 로드
require('dotenv').config();

class HealthChecker {
    constructor() {
        this.PORT = process.env.PORT || 3000;
        this.checks = [];
        this.startTime = Date.now();
    }

    log(message, type = 'info') {
        const timestamp = new Date().toISOString();
        const symbols = {
            info: '📋',
            success: '✅', 
            warning: '⚠️',
            error: '❌'
        };
        console.log(`${symbols[type]} ${timestamp} ${message}`);
    }

    async checkEnvironmentVariables() {
        this.log('환경 변수 검사 중...', 'info');
        
        const requiredVars = [
            'DATABASE_URL',
            'JWT_SECRET'
        ];
        
        const optionalVars = [
            'NODE_ENV',
            'PORT',
            'ADMIN_PASSWORD',
            'BCRYPT_SALT_ROUNDS'
        ];
        
        const missing = [];
        const present = [];
        
        // 필수 환경 변수 검사
        for (const varName of requiredVars) {
            if (!process.env[varName]) {
                missing.push(varName);
            } else {
                present.push(varName);
            }
        }
        
        // 선택적 환경 변수 검사
        for (const varName of optionalVars) {
            if (process.env[varName]) {
                present.push(`${varName} (선택사항)`);
            }
        }
        
        if (missing.length > 0) {
            this.log(`누락된 환경 변수: ${missing.join(', ')}`, 'error');
            return { success: false, missing, present };
        }
        
        this.log(`환경 변수 검사 완료 - ${present.length}개 확인됨`, 'success');
        return { success: true, missing: [], present };
    }

    async checkDatabaseConnection() {
        this.log('데이터베이스 연결 테스트 중...', 'info');
        
        if (!process.env.DATABASE_URL) {
            this.log('DATABASE_URL이 설정되지 않음', 'error');
            return { success: false, error: 'DATABASE_URL not configured' };
        }

        const pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
            connectionTimeoutMillis: 10000,
            statement_timeout: 5000
        });

        try {
            const startTime = Date.now();
            const client = await pool.connect();
            
            // 기본 연결 테스트
            const result = await client.query('SELECT NOW() as current_time, version() as db_version');
            const responseTime = Date.now() - startTime;
            
            // 테이블 존재 여부 확인
            const tableCheck = await client.query(`
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_schema = 'public' 
                  AND table_type = 'BASE TABLE'
                ORDER BY table_name
            `);
            
            client.release();
            await pool.end();
            
            const dbInfo = {
                connected: true,
                responseTime: `${responseTime}ms`,
                serverTime: result.rows[0].current_time,
                version: result.rows[0].db_version.split(' ')[0],
                tablesFound: tableCheck.rows.length,
                tableList: tableCheck.rows.map(row => row.table_name)
            };
            
            if (tableCheck.rows.length === 0) {
                this.log('데이터베이스 연결됨 - 테이블이 없음 (초기화 필요)', 'warning');
                dbInfo.needsInitialization = true;
            } else {
                this.log(`데이터베이스 연결 성공 - ${tableCheck.rows.length}개 테이블 확인`, 'success');
            }
            
            return { success: true, ...dbInfo };
            
        } catch (error) {
            this.log(`데이터베이스 연결 실패: ${error.message}`, 'error');
            return { 
                success: false, 
                error: error.message,
                code: error.code 
            };
        }
    }

    async checkPortAvailability() {
        this.log(`포트 ${this.PORT} 가용성 검사 중...`, 'info');
        
        return new Promise((resolve) => {
            const server = http.createServer();
            
            server.listen(this.PORT, () => {
                server.close(() => {
                    this.log(`포트 ${this.PORT} 사용 가능`, 'success');
                    resolve({ success: true, port: this.PORT, available: true });
                });
            });
            
            server.on('error', (error) => {
                if (error.code === 'EADDRINUSE') {
                    this.log(`포트 ${this.PORT}가 이미 사용 중`, 'warning');
                    resolve({ 
                        success: false, 
                        port: this.PORT, 
                        available: false, 
                        error: 'Port already in use' 
                    });
                } else {
                    this.log(`포트 검사 실패: ${error.message}`, 'error');
                    resolve({ 
                        success: false, 
                        port: this.PORT, 
                        error: error.message 
                    });
                }
            });
        });
    }

    async checkFileSystem() {
        this.log('파일 시스템 검사 중...', 'info');
        
        const requiredFiles = [
            'server.js',
            'package.json',
            'public/index.html'
        ];
        
        const requiredDirs = [
            'public',
            'scripts'
        ];
        
        const results = {
            files: { found: [], missing: [] },
            directories: { found: [], missing: [] },
            permissions: []
        };
        
        try {
            // 파일 존재 여부 확인
            for (const file of requiredFiles) {
                try {
                    const stats = await fs.stat(file);
                    if (stats.isFile()) {
                        results.files.found.push(file);
                        
                        // 실행 권한 확인 (server.js)
                        if (file === 'server.js') {
                            results.permissions.push({
                                file,
                                readable: true,
                                size: `${Math.round(stats.size / 1024)}KB`
                            });
                        }
                    }
                } catch (error) {
                    results.files.missing.push(file);
                }
            }
            
            // 디렉토리 존재 여부 확인
            for (const dir of requiredDirs) {
                try {
                    const stats = await fs.stat(dir);
                    if (stats.isDirectory()) {
                        results.directories.found.push(dir);
                    }
                } catch (error) {
                    results.directories.missing.push(dir);
                }
            }
            
            // 로그 디렉토리 생성 시도
            try {
                await fs.mkdir('logs', { recursive: true });
                results.directories.found.push('logs (created)');
            } catch (error) {
                this.log('로그 디렉토리 생성 실패', 'warning');
            }
            
            const success = results.files.missing.length === 0 && results.directories.missing.length === 0;
            
            if (success) {
                this.log(`파일 시스템 검사 완료 - 모든 필수 파일/디렉토리 확인됨`, 'success');
            } else {
                this.log(`파일 시스템 검사 실패 - 누락된 항목들이 있음`, 'error');
            }
            
            return { success, ...results };
            
        } catch (error) {
            this.log(`파일 시스템 검사 오류: ${error.message}`, 'error');
            return { success: false, error: error.message };
        }
    }

    async checkSystemResources() {
        this.log('시스템 리소스 검사 중...', 'info');
        
        const resources = {
            memory: process.memoryUsage(),
            uptime: process.uptime(),
            platform: process.platform,
            nodeVersion: process.version,
            arch: process.arch
        };
        
        // 메모리 사용량 체크 (MB 단위)
        const memoryMB = {
            rss: Math.round(resources.memory.rss / 1024 / 1024),
            heapTotal: Math.round(resources.memory.heapTotal / 1024 / 1024),
            heapUsed: Math.round(resources.memory.heapUsed / 1024 / 1024),
            external: Math.round(resources.memory.external / 1024 / 1024)
        };
        
        const warnings = [];
        
        // 메모리 사용량 경고 (500MB 이상)
        if (memoryMB.rss > 500) {
            warnings.push(`높은 메모리 사용량: ${memoryMB.rss}MB`);
        }
        
        // Node.js 버전 체크
        const nodeVersionMajor = parseInt(process.version.slice(1).split('.')[0]);
        if (nodeVersionMajor < 18) {
            warnings.push(`Node.js 버전이 낮음: ${process.version} (18+ 권장)`);
        }
        
        if (warnings.length > 0) {
            this.log(`시스템 리소스 경고: ${warnings.join(', ')}`, 'warning');
        } else {
            this.log('시스템 리소스 정상', 'success');
        }
        
        return {
            success: true,
            resources: {
                ...resources,
                memoryMB
            },
            warnings
        };
    }

    async checkSecuritySettings() {
        this.log('보안 설정 검사 중...', 'info');
        
        const security = {
            jwtSecret: !!process.env.JWT_SECRET,
            jwtSecretLength: process.env.JWT_SECRET ? process.env.JWT_SECRET.length : 0,
            adminPassword: !!process.env.ADMIN_PASSWORD,
            nodeEnv: process.env.NODE_ENV,
            bcryptRounds: process.env.BCRYPT_SALT_ROUNDS || '12'
        };
        
        const issues = [];
        const recommendations = [];
        
        // JWT 시크릿 검사
        if (!security.jwtSecret) {
            issues.push('JWT_SECRET이 설정되지 않음');
        } else if (security.jwtSecretLength < 32) {
            recommendations.push('JWT_SECRET이 너무 짧음 (32자 이상 권장)');
        }
        
        // 관리자 비밀번호 검사
        if (!security.adminPassword) {
            recommendations.push('ADMIN_PASSWORD가 설정되지 않음 (기본값 사용됨)');
        }
        
        // 프로덕션 환경 검사
        if (security.nodeEnv === 'production') {
            if (!security.adminPassword) {
                issues.push('프로덕션 환경에서 ADMIN_PASSWORD 필수');
            }
        }
        
        // bcrypt rounds 검사
        const rounds = parseInt(security.bcryptRounds);
        if (rounds < 10) {
            recommendations.push('BCRYPT_SALT_ROUNDS가 낮음 (12+ 권장)');
        }
        
        const success = issues.length === 0;
        
        if (success) {
            this.log('보안 설정 검사 완료', 'success');
        } else {
            this.log(`보안 설정 문제: ${issues.join(', ')}`, 'error');
        }
        
        if (recommendations.length > 0) {
            this.log(`보안 권장사항: ${recommendations.join(', ')}`, 'warning');
        }
        
        return {
            success,
            security,
            issues,
            recommendations
        };
    }

    async runAllChecks() {
        this.log('🚀 오성중학교 동아리 시스템 헬스체크 시작', 'info');
        this.log('='.repeat(60), 'info');
        
        const results = {
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            checks: {}
        };
        
        try {
            // 모든 검사 실행
            results.checks.environment = await this.checkEnvironmentVariables();
            results.checks.database = await this.checkDatabaseConnection();
            results.checks.port = await this.checkPortAvailability();
            results.checks.filesystem = await this.checkFileSystem();
            results.checks.resources = await this.checkSystemResources();
            results.checks.security = await this.checkSecuritySettings();
            
            // 전체 결과 평가
            const allPassed = Object.values(results.checks).every(check => check.success);
            const criticalFailed = !results.checks.environment.success || 
                                 !results.checks.database.success ||
                                 !results.checks.filesystem.success;
            
            results.overall = {
                status: allPassed ? 'healthy' : (criticalFailed ? 'critical' : 'warning'),
                passed: Object.values(results.checks).filter(c => c.success).length,
                total: Object.keys(results.checks).length,
                duration: `${Date.now() - this.startTime}ms`
            };
            
            this.log('='.repeat(60), 'info');
            
            if (allPassed) {
                this.log('🎉 모든 헬스체크 통과! 시스템 준비 완료', 'success');
                process.exit(0);
            } else if (criticalFailed) {
                this.log('💥 중요한 헬스체크 실패! 시스템 시작 불가', 'error');
                this.printSummary(results);
                process.exit(1);
            } else {
                this.log('⚠️ 일부 헬스체크 실패 - 경고 상태로 시작 가능', 'warning');
                this.printSummary(results);
                process.exit(0);
            }
            
        } catch (error) {
            this.log(`헬스체크 실행 중 오류: ${error.message}`, 'error');
            console.error(error.stack);
            process.exit(1);
        }
    }

    printSummary(results) {
        console.log('\n📊 헬스체크 요약:');
        console.log(`전체 상태: ${results.overall.status.toUpperCase()}`);
        console.log(`통과: ${results.overall.passed}/${results.overall.total}`);
        console.log(`실행 시간: ${results.overall.duration}`);
        
        console.log('\n📋 상세 결과:');
        for (const [checkName, result] of Object.entries(results.checks)) {
            const status = result.success ? '✅' : '❌';
            console.log(`  ${status} ${checkName}: ${result.success ? 'PASS' : 'FAIL'}`);
            
            if (!result.success && result.error) {
                console.log(`     오류: ${result.error}`);
            }
        }
        
        // 데이터베이스 초기화 필요 안내
        if (results.checks.database.success && results.checks.database.needsInitialization) {
            console.log('\n🔧 다음 단계:');
            console.log('  데이터베이스 테이블이 없습니다.');
            console.log('  서버 시작 후 /init-database 엔드포인트를 방문하여 초기화하세요.');
        }
    }
}

// 스크립트 실행
if (require.main === module) {
    const checker = new HealthChecker();
    checker.runAllChecks().catch((error) => {
        console.error('❌ 헬스체크 실행 실패:', error);
        process.exit(1);
    });
}

module.exports = HealthChecker;
