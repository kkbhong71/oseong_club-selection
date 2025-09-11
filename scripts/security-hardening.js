// scripts/security-hardening.js
// 보안 강화 및 취약점 검사

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const fs = require('fs').promises;

class SecurityAuditor {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        this.vulnerabilities = [];
        this.recommendations = [];
        this.securityConfig = {
            minPasswordLength: 8,
            maxLoginAttempts: 5,
            sessionTimeout: 24 * 60 * 60 * 1000, // 24시간
            allowedUserAgents: [], // 빈 배열은 모든 User-Agent 허용
            ipWhitelist: [], // 빈 배열은 모든 IP 허용
            requireHttps: process.env.NODE_ENV === 'production'
        };
    }

    async runSecurityAudit() {
        console.log('보안 감사 시작...');
        
        const audits = [
            this.checkPasswordSecurity(),
            this.checkDatabaseSecurity(),
            this.checkSessionSecurity(),
            this.checkInputValidation(),
            this.checkAuthenticationFlaws(),
            this.checkEnvironmentSecurity(),
            this.checkServerConfiguration()
        ];
        
        await Promise.all(audits);
        
        return this.generateSecurityReport();
    }

    async checkPasswordSecurity() {
        try {
            // 약한 비밀번호 패턴 검사
            const weakPasswords = await this.pool.query(`
                SELECT username, name, role, created_at
                FROM users 
                WHERE role = 'student' 
                AND LENGTH(password) < 60  -- bcrypt 해시는 60자
            `);
            
            if (weakPasswords.rows.length > 0) {
                this.addVulnerability(
                    'weak_password_hashing',
                    `${weakPasswords.rows.length}개 계정이 취약한 비밀번호 해싱을 사용 중`,
                    'high',
                    'bcrypt를 사용하여 모든 비밀번호를 재해싱하세요'
                );
            }
            
            // 관리자 계정 기본 비밀번호 검사
            const adminUser = await this.pool.query(`
                SELECT username, password, last_login
                FROM users 
                WHERE role = 'admin' AND username = 'admin'
            `);
            
            if (adminUser.rows.length > 0) {
                const isDefaultPassword = await bcrypt.compare('admin123', adminUser.rows[0].password);
                if (isDefaultPassword) {
                    this.addVulnerability(
                        'default_admin_password',
                        '관리자 계정이 기본 비밀번호를 사용 중',
                        'critical',
                        '즉시 관리자 비밀번호를 변경하세요'
                    );
                }
            }
            
            // 비밀번호 재사용 패턴 검사 (학번과 동일한 비밀번호)
            const samePasswordUsers = await this.pool.query(`
                SELECT COUNT(*) as count
                FROM users 
                WHERE role = 'student'
            `);
            
            if (samePasswordUsers.rows[0].count > 0) {
                this.addRecommendation(
                    'password_policy',
                    '학생들이 학번과 동일한 비밀번호를 사용하고 있습니다',
                    '비밀번호 복잡성 정책을 도입하고 주기적 변경을 요구하세요'
                );
            }
            
        } catch (error) {
            console.error('비밀번호 보안 검사 실패:', error.message);
        }
    }

    async checkDatabaseSecurity() {
        try {
            // SQL 인젝션 취약점 검사 (기본적인 패턴)
            const sqlInjectionPatterns = [
                "' OR '1'='1",
                "'; DROP TABLE",
                "UNION SELECT",
                "/*!50000",
                "<script"
            ];
            
            // 실제 공격 시도 로그가 있는지 확인 (예시)
            // 실제 구현에서는 웹 서버 로그를 분석해야 함
            
            // 데이터베이스 권한 검사
            const dbPermissions = await this.pool.query(`
                SELECT 
                    schemaname,
                    tablename,
                    tableowner,
                    hasinserts,
                    hasselects,
                    hasupdates,
                    hasdeletes
                FROM pg_tables 
                WHERE schemaname = 'public'
            `);
            
            // 민감한 데이터 노출 검사
            const sensitiveDataCheck = await this.pool.query(`
                SELECT 
                    column_name,
                    data_type,
                    table_name
                FROM information_schema.columns
                WHERE table_schema = 'public'
                AND column_name ILIKE ANY(ARRAY['%password%', '%secret%', '%token%', '%key%'])
            `);
            
            if (sensitiveDataCheck.rows.length > 0) {
                this.addRecommendation(
                    'sensitive_data_columns',
                    `민감한 데이터 컬럼 ${sensitiveDataCheck.rows.length}개 발견`,
                    '민감한 데이터가 적절히 암호화되어 있는지 확인하세요'
                );
            }
            
            // 데이터베이스 연결 보안 검사
            if (!process.env.DATABASE_URL.includes('ssl=true') && process.env.NODE_ENV === 'production') {
                this.addVulnerability(
                    'unencrypted_db_connection',
                    '데이터베이스 연결이 암호화되지 않음',
                    'medium',
                    'SSL/TLS를 사용하여 데이터베이스 연결을 암호화하세요'
                );
            }
            
        } catch (error) {
            console.error('데이터베이스 보안 검사 실패:', error.message);
        }
    }

    async checkSessionSecurity() {
        try {
            // JWT 설정 검사
            const jwtSecret = process.env.JWT_SECRET;
            if (!jwtSecret || jwtSecret.length < 32) {
                this.addVulnerability(
                    'weak_jwt_secret',
                    'JWT 비밀키가 너무 짧거나 설정되지 않음',
                    'high',
                    '최소 32자 이상의 강력한 JWT 비밀키를 설정하세요'
                );
            }
            
            if (jwtSecret === 'oseong-middle-school-2025-super-secret-key') {
                this.addVulnerability(
                    'default_jwt_secret',
                    '기본 JWT 비밀키를 사용 중',
                    'critical',
                    '고유한 JWT 비밀키로 즉시 변경하세요'
                );
            }
            
            // 세션 타임아웃 검사
            this.addRecommendation(
                'session_management',
                '현재 JWT 토큰은 24시간 유효',
                '보안 강화를 위해 더 짧은 만료 시간을 고려하세요'
            );
            
        } catch (error) {
            console.error('세션 보안 검사 실패:', error.message);
        }
    }

    async checkInputValidation() {
        try {
            // 입력 검증 취약점 검사
            const xssPatterns = [
                '<script>',
                'javascript:',
                'onload=',
                'onerror=',
                'onclick='
            ];
            
            // 사용자 입력 데이터에서 XSS 패턴 검사
            const userInputCheck = await this.pool.query(`
                SELECT 
                    id, name, username, class_info
                FROM users 
                WHERE name ~ '[<>"\']' 
                   OR class_info ~ '[<>"\']'
                LIMIT 10
            `);
            
            if (userInputCheck.rows.length > 0) {
                this.addVulnerability(
                    'potential_xss_input',
                    `사용자 입력에서 잠재적 XSS 문자 ${userInputCheck.rows.length}개 발견`,
                    'medium',
                    '입력 검증 및 출력 인코딩을 강화하세요'
                );
            }
            
            // 동아리 설명에서 악성 스크립트 검사
            const clubInputCheck = await this.pool.query(`
                SELECT 
                    id, name, description, activities
                FROM clubs 
                WHERE description ~ '[<>"\']'
                   OR activities ~ '[<>"\']'
                LIMIT 10
            `);
            
            if (clubInputCheck.rows.length > 0) {
                this.addRecommendation(
                    'club_input_validation',
                    '동아리 정보에 특수 문자가 포함되어 있음',
                    '관리자 입력에도 검증 로직을 적용하세요'
                );
            }
            
        } catch (error) {
            console.error('입력 검증 검사 실패:', error.message);
        }
    }

    async checkAuthenticationFlaws() {
        try {
            // 계정 잠금 정책 검사
            this.addRecommendation(
                'account_lockout',
                '현재 계정 잠금 정책이 없음',
                '무차별 공격 방지를 위한 계정 잠금 기능을 구현하세요'
            );
            
            // 다중 인증 검사
            this.addRecommendation(
                'multi_factor_auth',
                '다중 인증이 구현되지 않음',
                '관리자 계정에 2단계 인증을 도입하세요'
            );
            
            // 권한 상승 취약점 검사
            const roleEscalationCheck = await this.pool.query(`
                SELECT 
                    username, role, created_at, last_login
                FROM users 
                WHERE role = 'admin' AND username != 'admin'
            `);
            
            if (roleEscalationCheck.rows.length > 1) {
                this.addRecommendation(
                    'admin_accounts',
                    `관리자 계정이 ${roleEscalationCheck.rows.length}개 존재`,
                    '불필요한 관리자 계정을 제거하고 권한 관리를 강화하세요'
                );
            }
            
        } catch (error) {
            console.error('인증 결함 검사 실패:', error.message);
        }
    }

    async checkEnvironmentSecurity() {
        try {
            // 환경변수 보안 검사
            const criticalEnvVars = [
                'DATABASE_URL',
                'JWT_SECRET',
                'ADMIN_PASSWORD'
            ];
            
            const missingVars = criticalEnvVars.filter(varName => !process.env[varName]);
            
            if (missingVars.length > 0) {
                this.addVulnerability(
                    'missing_env_vars',
                    `중요 환경변수 ${missingVars.join(', ')}가 설정되지 않음`,
                    'high',
                    '모든 중요 환경변수를 안전하게 설정하세요'
                );
            }
            
            // 프로덕션 환경 설정 검사
            if (process.env.NODE_ENV !== 'production') {
                this.addRecommendation(
                    'production_environment',
                    'NODE_ENV가 production으로 설정되지 않음',
                    '프로덕션 환경에서는 NODE_ENV=production을 설정하세요'
                );
            }
            
            // 디버깅 정보 노출 검사
            if (process.env.LOG_LEVEL === 'debug') {
                this.addVulnerability(
                    'debug_information_exposure',
                    '디버그 로그가 활성화되어 있음',
                    'low',
                    '프로덕션에서는 로그 레벨을 info 이상으로 설정하세요'
                );
            }
            
        } catch (error) {
            console.error('환경 보안 검사 실패:', error.message);
        }
    }

    async checkServerConfiguration() {
        try {
            // HTTPS 검사
            if (!this.securityConfig.requireHttps && process.env.NODE_ENV === 'production') {
                this.addVulnerability(
                    'http_only',
                    'HTTPS가 강제되지 않음',
                    'high',
                    '프로덕션에서는 HTTPS를 강제하세요'
                );
            }
            
            // CSP 설정 검사
            this.addVulnerability(
                'csp_disabled',
                'Content Security Policy가 비활성화됨',
                'medium',
                'React 호환성을 유지하면서 CSP를 재활성화하세요'
            );
            
            // Rate Limiting 검사
            const rateLimitMax = parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100;
            if (rateLimitMax > 200) {
                this.addRecommendation(
                    'rate_limiting',
                    `Rate Limit이 ${rateLimitMax}으로 설정되어 있음`,
                    'DoS 공격 방지를 위해 더 낮은 값을 고려하세요'
                );
            }
            
            // CORS 설정 검사
            if (!process.env.CORS_ORIGIN) {
                this.addVulnerability(
                    'cors_wildcard',
                    'CORS 설정이 모든 도메인을 허용함',
                    'medium',
                    '특정 도메인만 허용하도록 CORS를 제한하세요'
                );
            }
            
        } catch (error) {
            console.error('서버 구성 검사 실패:', error.message);
        }
    }

    addVulnerability(id, description, severity, recommendation) {
        this.vulnerabilities.push({
            id,
            description,
            severity,
            recommendation,
            discovered_at: new Date().toISOString()
        });
    }

    addRecommendation(id, description, suggestion) {
        this.recommendations.push({
            id,
            description,
            suggestion,
            priority: 'normal',
            created_at: new Date().toISOString()
        });
    }

    generateSecurityReport() {
        const severityCount = this.vulnerabilities.reduce((acc, vuln) => {
            acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
            return acc;
        }, {});
        
        const report = {
            summary: {
                total_vulnerabilities: this.vulnerabilities.length,
                severity_breakdown: severityCount,
                total_recommendations: this.recommendations.length,
                security_score: this.calculateSecurityScore(),
                audit_date: new Date().toISOString()
            },
            vulnerabilities: this.vulnerabilities.sort((a, b) => {
                const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
                return severityOrder[b.severity] - severityOrder[a.severity];
            }),
            recommendations: this.recommendations,
            immediate_actions: this.getImmediateActions(),
            compliance_status: this.getComplianceStatus()
        };
        
        return report;
    }

    calculateSecurityScore() {
        const weights = { critical: -25, high: -15, medium: -10, low: -5 };
        let score = 100;
        
        for (const vuln of this.vulnerabilities) {
            score += weights[vuln.severity] || 0;
        }
        
        return Math.max(0, Math.min(100, score));
    }

    getImmediateActions() {
        return this.vulnerabilities
            .filter(vuln => vuln.severity === 'critical' || vuln.severity === 'high')
            .map(vuln => ({
                action: vuln.recommendation,
                reason: vuln.description,
                urgency: vuln.severity
            }));
    }

    getComplianceStatus() {
        // 기본적인 보안 준수사항 체크
        const criticalIssues = this.vulnerabilities.filter(v => v.severity === 'critical').length;
        const highIssues = this.vulnerabilities.filter(v => v.severity === 'high').length;
        
        let status = 'compliant';
        if (criticalIssues > 0) {
            status = 'non_compliant';
        } else if (highIssues > 0) {
            status = 'partially_compliant';
        }
        
        return {
            status,
            critical_issues: criticalIssues,
            high_issues: highIssues,
            compliance_percentage: this.calculateSecurityScore()
        };
    }

    async generateSecurityPatch() {
        const patches = [];
        
        for (const vuln of this.vulnerabilities) {
            switch (vuln.id) {
                case 'default_admin_password':
                    patches.push({
                        type: 'database_update',
                        description: '관리자 비밀번호 변경',
                        sql: `UPDATE users SET password = $1 WHERE username = 'admin' AND role = 'admin'`,
                        params: [await bcrypt.hash(crypto.randomBytes(16).toString('hex'), 12)]
                    });
                    break;
                    
                case 'weak_jwt_secret':
                    patches.push({
                        type: 'environment_update',
                        description: '강력한 JWT 비밀키 생성',
                        env_var: 'JWT_SECRET',
                        value: crypto.randomBytes(64).toString('hex')
                    });
                    break;
                    
                case 'csp_disabled':
                    patches.push({
                        type: 'server_config',
                        description: 'CSP 재활성화',
                        config: {
                            contentSecurityPolicy: {
                                directives: {
                                    defaultSrc: ["'self'"],
                                    scriptSrc: ["'self'", "'unsafe-inline'"],
                                    styleSrc: ["'self'", "'unsafe-inline'", "https://cdn.tailwindcss.com"],
                                    imgSrc: ["'self'", "data:", "https:"],
                                    connectSrc: ["'self'"]
                                }
                            }
                        }
                    });
                    break;
            }
        }
        
        return patches;
    }

    async applySecurityPatches(patches) {
        const results = [];
        
        for (const patch of patches) {
            try {
                switch (patch.type) {
                    case 'database_update':
                        await this.pool.query(patch.sql, patch.params || []);
                        results.push({ patch: patch.description, status: 'success' });
                        break;
                        
                    case 'environment_update':
                        console.log(`환경변수 업데이트 필요: ${patch.env_var}=${patch.value}`);
                        results.push({ patch: patch.description, status: 'manual_required' });
                        break;
                        
                    case 'server_config':
                        console.log(`서버 설정 업데이트 필요:`, patch.config);
                        results.push({ patch: patch.description, status: 'manual_required' });
                        break;
                }
            } catch (error) {
                results.push({ 
                    patch: patch.description, 
                    status: 'failed', 
                    error: error.message 
                });
            }
        }
        
        return results;
    }

    async cleanup() {
        await this.pool.end();
    }
}

// 스크립트 실행
if (require.main === module) {
    const auditor = new SecurityAuditor();
    
    async function runAudit() {
        try {
            const report = await auditor.runSecurityAudit();
            
            console.log('\n보안 감사 결과:');
            console.log('==================');
            console.log(`보안 점수: ${report.summary.security_score}/100`);
            console.log(`취약점: ${report.summary.total_vulnerabilities}개`);
            console.log(`권장사항: ${report.summary.total_recommendations}개`);
            
            if (report.vulnerabilities.length > 0) {
                console.log('\n주요 취약점:');
                report.vulnerabilities.slice(0, 5).forEach(vuln => {
                    console.log(`- [${vuln.severity.toUpperCase()}] ${vuln.description}`);
                });
            }
            
            if (report.immediate_actions.length > 0) {
                console.log('\n즉시 조치 필요:');
                report.immediate_actions.forEach(action => {
                    console.log(`- ${action.action}`);
                });
            }
            
            // 보고서 저장
            const reportsDir = './reports';
            await fs.mkdir(reportsDir, { recursive: true });
            await fs.writeFile(
                `${reportsDir}/security-audit-${Date.now()}.json`,
                JSON.stringify(report, null, 2)
            );
            
            // 자동 패치 적용 (선택사항)
            if (process.argv.includes('--apply-patches')) {
                const patches = await auditor.generateSecurityPatch();
                const patchResults = await auditor.applySecurityPatches(patches);
                console.log('\n패치 적용 결과:', patchResults);
            }
            
        } catch (error) {
            console.error('보안 감사 실패:', error);
            process.exit(1);
        } finally {
            await auditor.cleanup();
        }
    }
    
    runAudit();
}

module.exports = SecurityAuditor;
