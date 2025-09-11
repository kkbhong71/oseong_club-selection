// scripts/performance-optimizer.js
// 성능 측정, 분석 및 최적화 도구

const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');
const { performance } = require('perf_hooks');

class PerformanceOptimizer {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        this.metrics = {
            queries: [],
            api_calls: [],
            memory_usage: [],
            response_times: []
        };
        
        this.optimizations = [];
        this.recommendations = [];
    }

    // 데이터베이스 성능 분석
    async analyzeDatabasePerformance() {
        console.log('데이터베이스 성능 분석 시작...');
        
        try {
            // 느린 쿼리 분석
            const slowQueries = await this.identifySlowQueries();
            
            // 인덱스 효율성 분석
            const indexAnalysis = await this.analyzeIndexEfficiency();
            
            // 테이블 통계 분석
            const tableStats = await this.analyzeTableStatistics();
            
            // 연결 풀 분석
            const connectionAnalysis = await this.analyzeConnectionPool();
            
            return {
                slow_queries: slowQueries,
                index_efficiency: indexAnalysis,
                table_statistics: tableStats,
                connection_pool: connectionAnalysis,
                recommendations: this.generateDatabaseRecommendations()
            };
            
        } catch (error) {
            console.error('데이터베이스 성능 분석 실패:', error.message);
            throw error;
        }
    }

    async identifySlowQueries() {
        try {
            // PostgreSQL slow query 로그 분석 (pg_stat_statements 확장 필요)
            const slowQueries = await this.pool.query(`
                SELECT 
                    query,
                    calls,
                    total_time,
                    mean_time,
                    max_time,
                    stddev_time,
                    rows
                FROM pg_stat_statements 
                WHERE mean_time > 100  -- 100ms 이상
                ORDER BY mean_time DESC 
                LIMIT 10
            `).catch(() => {
                // pg_stat_statements가 없으면 기본 쿼리로 대체
                return { rows: [] };
            });
            
            // 수동으로 주요 쿼리들의 성능 측정
            const testQueries = [
                {
                    name: 'user_login_query',
                    sql: 'SELECT id, username, password, name, role, class_info FROM users WHERE username = $1',
                    params: ['1101']
                },
                {
                    name: 'clubs_list_query', 
                    sql: `SELECT c.*, COUNT(a.id) as application_count 
                          FROM clubs c LEFT JOIN applications a ON c.id = a.club_id 
                          GROUP BY c.id ORDER BY c.name`,
                    params: []
                },
                {
                    name: 'student_applications_query',
                    sql: `SELECT a.*, c.name as club_name, c.teacher 
                          FROM applications a JOIN clubs c ON a.club_id = c.id 
                          WHERE a.user_id = $1 ORDER BY a.priority`,
                    params: [1]
                }
            ];
            
            const manualResults = [];
            for (const query of testQueries) {
                const startTime = performance.now();
                const result = await this.pool.query(query.sql, query.params);
                const endTime = performance.now();
                
                manualResults.push({
                    name: query.name,
                    execution_time: endTime - startTime,
                    rows_returned: result.rows.length,
                    query: query.sql
                });
            }
            
            return {
                pg_stat_statements: slowQueries.rows,
                manual_tests: manualResults
            };
            
        } catch (error) {
            console.error('느린 쿼리 분석 실패:', error.message);
            return { error: error.message };
        }
    }

    async analyzeIndexEfficiency() {
        try {
            // 인덱스 사용 통계
            const indexUsage = await this.pool.query(`
                SELECT 
                    schemaname,
                    tablename,
                    indexname,
                    idx_tup_read,
                    idx_tup_fetch,
                    idx_scan,
                    CASE 
                        WHEN idx_scan = 0 THEN 'unused'
                        WHEN idx_scan < 100 THEN 'low_usage'
                        ELSE 'active'
                    END as usage_level
                FROM pg_stat_user_indexes 
                WHERE schemaname = 'public'
                ORDER BY idx_scan DESC
            `);
            
            // 테이블 스캔 vs 인덱스 스캔 비율
            const scanRatio = await this.pool.query(`
                SELECT 
                    schemaname,
                    tablename,
                    seq_scan,
                    seq_tup_read,
                    idx_scan,
                    idx_tup_fetch,
                    CASE 
                        WHEN seq_scan + idx_scan = 0 THEN 0
                        ELSE ROUND((idx_scan::float / (seq_scan + idx_scan)) * 100, 2)
                    END as index_usage_percentage
                FROM pg_stat_user_tables 
                WHERE schemaname = 'public'
                ORDER BY index_usage_percentage ASC
            `);
            
            return {
                index_usage: indexUsage.rows,
                scan_ratios: scanRatio.rows
            };
            
        } catch (error) {
            console.error('인덱스 효율성 분석 실패:', error.message);
            return { error: error.message };
        }
    }

    async analyzeTableStatistics() {
        try {
            // 테이블 크기 및 활동 분석
            const tableStats = await this.pool.query(`
                SELECT 
                    schemaname,
                    tablename,
                    n_tup_ins as inserts,
                    n_tup_upd as updates,
                    n_tup_del as deletes,
                    n_live_tup as live_tuples,
                    n_dead_tup as dead_tuples,
                    last_vacuum,
                    last_autovacuum,
                    last_analyze,
                    last_autoanalyze,
                    pg_size_pretty(pg_total_relation_size(schemaname||'.'||tablename)) as table_size
                FROM pg_stat_user_tables 
                WHERE schemaname = 'public'
                ORDER BY pg_total_relation_size(schemaname||'.'||tablename) DESC
            `);
            
            return tableStats.rows;
            
        } catch (error) {
            console.error('테이블 통계 분석 실패:', error.message);
            return { error: error.message };
        }
    }

    async analyzeConnectionPool() {
        try {
            // 현재 연결 상태
            const connectionStats = await this.pool.query(`
                SELECT 
                    state,
                    COUNT(*) as count,
                    AVG(EXTRACT(EPOCH FROM (now() - state_change))) as avg_duration_seconds
                FROM pg_stat_activity 
                WHERE datname = current_database()
                GROUP BY state
            `);
            
            // 연결 풀 설정 정보
            const poolInfo = {
                total_connections: this.pool.totalCount,
                idle_connections: this.pool.idleCount,
                waiting_count: this.pool.waitingCount,
                max_connections: this.pool.options.max,
                connection_timeout: this.pool.options.connectionTimeoutMillis,
                idle_timeout: this.pool.options.idleTimeoutMillis
            };
            
            return {
                database_connections: connectionStats.rows,
                pool_status: poolInfo
            };
            
        } catch (error) {
            console.error('연결 풀 분석 실패:', error.message);
            return { error: error.message };
        }
    }

    generateDatabaseRecommendations() {
        const recommendations = [];
        
        // 기본 성능 권장사항
        recommendations.push({
            category: 'indexing',
            priority: 'high',
            description: '자주 조회되는 컬럼에 인덱스 추가',
            implementation: `
                CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                CREATE INDEX IF NOT EXISTS idx_applications_user_club ON applications(user_id, club_id);
                CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
            `
        });
        
        recommendations.push({
            category: 'query_optimization',
            priority: 'medium',
            description: '복잡한 JOIN 쿼리 최적화',
            implementation: `
                -- 동아리 목록 조회 시 서브쿼리 대신 LEFT JOIN 사용
                -- 필요한 컬럼만 SELECT하여 데이터 전송량 최소화
            `
        });
        
        recommendations.push({
            category: 'maintenance',
            priority: 'low',
            description: '정기적인 VACUUM 및 ANALYZE 실행',
            implementation: `
                -- 매주 실행
                VACUUM ANALYZE;
                
                -- 월간 실행
                VACUUM FULL;
            `
        });
        
        return recommendations;
    }

    // API 성능 측정
    async measureAPIPerformance() {
        console.log('API 성능 측정 시작...');
        
        const baseUrl = process.env.TEST_URL || 'http://localhost:3000';
        const endpoints = [
            { path: '/api/health', method: 'GET' },
            { path: '/api/clubs', method: 'GET' },
            { path: '/check-database', method: 'GET' }
        ];
        
        const results = [];
        
        for (const endpoint of endpoints) {
            try {
                const measurements = await this.measureEndpoint(baseUrl + endpoint.path, endpoint.method);
                results.push({
                    endpoint: endpoint.path,
                    method: endpoint.method,
                    ...measurements
                });
            } catch (error) {
                results.push({
                    endpoint: endpoint.path,
                    method: endpoint.method,
                    error: error.message,
                    success: false
                });
            }
        }
        
        return results;
    }

    async measureEndpoint(url, method = 'GET') {
        const measurements = [];
        const iterations = 5;
        
        for (let i = 0; i < iterations; i++) {
            const startTime = performance.now();
            const startMemory = process.memoryUsage();
            
            try {
                const response = await fetch(url, { method });
                const endTime = performance.now();
                const endMemory = process.memoryUsage();
                
                const responseTime = endTime - startTime;
                const memoryDelta = endMemory.heapUsed - startMemory.heapUsed;
                
                measurements.push({
                    response_time: responseTime,
                    status_code: response.status,
                    memory_delta: memoryDelta,
                    success: response.ok
                });
                
                // 요청 간격
                await new Promise(resolve => setTimeout(resolve, 100));
                
            } catch (error) {
                measurements.push({
                    response_time: performance.now() - startTime,
                    error: error.message,
                    success: false
                });
            }
        }
        
        // 통계 계산
        const successfulMeasurements = measurements.filter(m => m.success);
        const responseTimes = successfulMeasurements.map(m => m.response_time);
        
        if (responseTimes.length === 0) {
            return {
                success: false,
                error: 'All requests failed'
            };
        }
        
        return {
            success: true,
            avg_response_time: responseTimes.reduce((a, b) => a + b, 0) / responseTimes.length,
            min_response_time: Math.min(...responseTimes),
            max_response_time: Math.max(...responseTimes),
            success_rate: (successfulMeasurements.length / measurements.length) * 100,
            measurements: measurements
        };
    }

    // 메모리 사용량 최적화
    async analyzeMemoryUsage() {
        console.log('메모리 사용량 분석 시작...');
        
        const initialMemory = process.memoryUsage();
        
        // 가비지 컬렉션 강제 실행
        if (global.gc) {
            global.gc();
        }
        
        const afterGCMemory = process.memoryUsage();
        
        // 메모리 누수 감지를 위한 장기 모니터링
        const memoryHistory = [];
        for (let i = 0; i < 10; i++) {
            await new Promise(resolve => setTimeout(resolve, 1000));
            memoryHistory.push({
                timestamp: new Date().toISOString(),
                ...process.memoryUsage()
            });
        }
        
        return {
            initial_memory: initialMemory,
            after_gc_memory: afterGCMemory,
            memory_freed_by_gc: initialMemory.heapUsed - afterGCMemory.heapUsed,
            memory_history: memoryHistory,
            recommendations: this.generateMemoryRecommendations(memoryHistory)
        };
    }

    generateMemoryRecommendations(memoryHistory) {
        const recommendations = [];
        
        // 메모리 사용량 증가 추세 확인
        const heapUsages = memoryHistory.map(m => m.heapUsed);
        const isIncreasing = heapUsages[heapUsages.length - 1] > heapUsages[0];
        
        if (isIncreasing) {
            recommendations.push({
                type: 'memory_leak_suspected',
                description: '메모리 사용량이 지속적으로 증가하고 있습니다',
                suggestion: '메모리 누수 확인 및 객체 참조 정리 필요'
            });
        }
        
        const avgHeapUsed = heapUsages.reduce((a, b) => a + b, 0) / heapUsages.length;
        const maxRecommended = 512 * 1024 * 1024; // 512MB
        
        if (avgHeapUsed > maxRecommended) {
            recommendations.push({
                type: 'high_memory_usage',
                description: `평균 메모리 사용량이 ${Math.round(avgHeapUsed / 1024 / 1024)}MB입니다`,
                suggestion: '메모리 최적화 또는 서버 리소스 증설 검토'
            });
        }
        
        return recommendations;
    }

    // 전체 성능 보고서 생성
    async generatePerformanceReport() {
        console.log('종합 성능 보고서 생성 중...');
        
        try {
            const [dbAnalysis, apiPerformance, memoryAnalysis] = await Promise.all([
                this.analyzeDbPerformance(),
                this.measureAPIPerformance(),
                this.analyzeMemoryUsage()
            ]);
            
            const report = {
                timestamp: new Date().toISOString(),
                summary: {
                    overall_score: this.calculateOverallScore(dbAnalysis, apiPerformance, memoryAnalysis),
                    database_health: this.evaluateDBHealth(dbAnalysis),
                    api_health: this.evaluateAPIHealth(apiPerformance),
                    memory_health: this.evaluateMemoryHealth(memoryAnalysis)
                },
                detailed_analysis: {
                    database: dbAnalysis,
                    api_performance: apiPerformance,
                    memory_usage: memoryAnalysis
                },
                recommendations: this.consolidateRecommendations(),
                performance_trends: await this.getPerformanceTrends()
            };
            
            // 보고서 저장
            await this.saveReport(report);
            
            return report;
            
        } catch (error) {
            console.error('성능 보고서 생성 실패:', error.message);
            throw error;
        }
    }

    calculateOverallScore(dbAnalysis, apiPerformance, memoryAnalysis) {
        let score = 100;
        
        // 데이터베이스 점수 (40%)
        if (dbAnalysis.error) score -= 40;
        else {
            const avgResponseTime = dbAnalysis.slow_queries?.manual_tests?.reduce((sum, q) => sum + q.execution_time, 0) / 
                                  (dbAnalysis.slow_queries?.manual_tests?.length || 1);
            if (avgResponseTime > 100) score -= 20;
            else if (avgResponseTime > 50) score -= 10;
        }
        
        // API 점수 (40%)
        const failedAPIs = apiPerformance.filter(api => !api.success).length;
        score -= failedAPIs * 10;
        
        const slowAPIs = apiPerformance.filter(api => api.avg_response_time > 2000).length;
        score -= slowAPIs * 5;
        
        // 메모리 점수 (20%)
        const avgMemory = memoryAnalysis.memory_history?.reduce((sum, m) => sum + m.heapUsed, 0) / 
                         (memoryAnalysis.memory_history?.length || 1);
        if (avgMemory > 512 * 1024 * 1024) score -= 15;
        else if (avgMemory > 256 * 1024 * 1024) score -= 5;
        
        return Math.max(0, Math.min(100, score));
    }

    evaluateDBHealth(analysis) {
        if (analysis.error) return 'critical';
        
        const avgResponseTime = analysis.slow_queries?.manual_tests?.reduce((sum, q) => sum + q.execution_time, 0) / 
                               (analysis.slow_queries?.manual_tests?.length || 1);
        
        if (avgResponseTime > 200) return 'poor';
        if (avgResponseTime > 100) return 'fair';
        if (avgResponseTime > 50) return 'good';
        return 'excellent';
    }

    evaluateAPIHealth(performance) {
        const successRate = performance.reduce((sum, api) => sum + (api.success_rate || 0), 0) / performance.length;
        const avgResponseTime = performance.reduce((sum, api) => sum + (api.avg_response_time || 0), 0) / performance.length;
        
        if (successRate < 90 || avgResponseTime > 3000) return 'critical';
        if (successRate < 95 || avgResponseTime > 2000) return 'poor';
        if (successRate < 99 || avgResponseTime > 1000) return 'fair';
        return 'excellent';
    }

    evaluateMemoryHealth(analysis) {
        const avgMemory = analysis.memory_history?.reduce((sum, m) => sum + m.heapUsed, 0) / 
                         (analysis.memory_history?.length || 1);
        
        if (avgMemory > 512 * 1024 * 1024) return 'critical';
        if (avgMemory > 384 * 1024 * 1024) return 'poor';
        if (avgMemory > 256 * 1024 * 1024) return 'fair';
        return 'excellent';
    }

    consolidateRecommendations() {
        // 모든 추천사항을 우선순위별로 정리
        return [
            ...this.generateDatabaseRecommendations(),
            {
                category: 'caching',
                priority: 'medium',
                description: 'Redis 캐싱 도입으로 API 응답 속도 개선',
                implementation: 'npm install redis, 자주 조회되는 데이터 캐싱'
            },
            {
                category: 'cdn',
                priority: 'low',
                description: 'CDN 도입으로 정적 파일 로딩 속도 개선',
                implementation: 'Cloudflare 또는 AWS CloudFront 설정'
            }
        ];
    }

    async getPerformanceTrends() {
        // 이전 성능 보고서들과 비교하여 트렌드 분석
        try {
            const reportsDir = path.join(__dirname, '..', 'reports');
            const files = await fs.readdir(reportsDir).catch(() => []);
            const performanceFiles = files.filter(f => f.startsWith('performance-report-'));
            
            const trends = [];
            for (const file of performanceFiles.slice(-5)) { // 최근 5개 보고서만
                try {
                    const content = await fs.readFile(path.join(reportsDir, file), 'utf8');
                    const report = JSON.parse(content);
                    trends.push({
                        timestamp: report.timestamp,
                        overall_score: report.summary.overall_score,
                        database_health: report.summary.database_health,
                        api_health: report.summary.api_health,
                        memory_health: report.summary.memory_health
                    });
                } catch (error) {
                    console.warn(`보고서 파일 읽기 실패: ${file}`);
                }
            }
            
            return trends.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            
        } catch (error) {
            return [];
        }
    }

    async saveReport(report) {
        try {
            const reportsDir = path.join(__dirname, '..', 'reports');
            await fs.mkdir(reportsDir, { recursive: true });
            
            const filename = `performance-report-${Date.now()}.json`;
            const filepath = path.join(reportsDir, filename);
            
            await fs.writeFile(filepath, JSON.stringify(report, null, 2));
            console.log(`성능 보고서 저장됨: ${filename}`);
            
            return filename;
            
        } catch (error) {
            console.error('보고서 저장 실패:', error.message);
        }
    }

    async cleanup() {
        await this.pool.end();
    }
}

// CLI 실행
if (require.main === module) {
    const optimizer = new PerformanceOptimizer();
    
    async function runOptimization() {
        try {
            const command = process.argv[2] || 'full';
            
            switch (command) {
                case 'database':
                    const dbResult = await optimizer.analyzeDbPerformance();
                    console.log('데이터베이스 분석 결과:', JSON.stringify(dbResult, null, 2));
                    break;
                    
                case 'api':
                    const apiResult = await optimizer.measureAPIPerformance();
                    console.log('API 성능 결과:', JSON.stringify(apiResult, null, 2));
                    break;
                    
                case 'memory':
                    const memResult = await optimizer.analyzeMemoryUsage();
                    console.log('메모리 분석 결과:', JSON.stringify(memResult, null, 2));
                    break;
                    
                case 'full':
                default:
                    const report = await optimizer.generatePerformanceReport();
                    console.log('\n성능 보고서 요약:');
                    console.log(`전체 점수: ${report.summary.overall_score}/100`);
                    console.log(`데이터베이스: ${report.summary.database_health}`);
                    console.log(`API 성능: ${report.summary.api_health}`);
                    console.log(`메모리 상태: ${report.summary.memory_health}`);
                    
                    if (report.recommendations.length > 0) {
                        console.log('\n주요 개선사항:');
                        report.recommendations.slice(0, 3).forEach(rec => {
                            console.log(`- [${rec.priority}] ${rec.description}`);
                        });
                    }
                    break;
            }
            
        } catch (error) {
            console.error('성능 최적화 실행 실패:', error);
            process.exit(1);
        } finally {
            await optimizer.cleanup();
        }
    }
    
    runOptimization();
}

module.exports = PerformanceOptimizer;
