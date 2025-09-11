// scripts/monitoring.js
// 실시간 시스템 모니터링 및 알림

const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');

class SystemMonitor {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        this.metrics = {
            lastCheck: null,
            errors: [],
            performance: {},
            alerts: []
        };
        
        this.thresholds = {
            maxResponseTime: 5000,
            maxErrorRate: 5,
            maxMemoryUsage: 512, // MB
            maxDbConnections: 15
        };
    }

    async checkDatabaseHealth() {
        const start = Date.now();
        
        try {
            // 기본 연결 테스트
            const connectionTest = await this.pool.query('SELECT NOW()');
            const connectionTime = Date.now() - start;
            
            // 활성 연결 수 체크
            const connectionsQuery = await this.pool.query(`
                SELECT count(*) as active_connections 
                FROM pg_stat_activity 
                WHERE state = 'active'
            `);
            const activeConnections = parseInt(connectionsQuery.rows[0].active_connections);
            
            // 테이블 상태 체크
            const tablesQuery = await this.pool.query(`
                SELECT 
                    schemaname,
                    tablename,
                    n_tup_ins as inserts,
                    n_tup_upd as updates,
                    n_tup_del as deletes,
                    n_live_tup as live_tuples,
                    n_dead_tup as dead_tuples
                FROM pg_stat_user_tables
                WHERE schemaname = 'public'
            `);
            
            // 데이터베이스 크기
            const sizeQuery = await this.pool.query(`
                SELECT pg_size_pretty(pg_database_size(current_database())) as db_size
            `);
            
            return {
                status: 'healthy',
                connection_time: connectionTime,
                active_connections: activeConnections,
                tables: tablesQuery.rows,
                database_size: sizeQuery.rows[0].db_size,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            return {
                status: 'error',
                error: error.message,
                connection_time: Date.now() - start,
                timestamp: new Date().toISOString()
            };
        }
    }

    async checkApplicationMetrics() {
        try {
            // 사용자 통계
            const userStats = await this.pool.query(`
                SELECT 
                    role,
                    COUNT(*) as count,
                    COUNT(CASE WHEN last_login > NOW() - INTERVAL '24 hours' THEN 1 END) as daily_active,
                    COUNT(CASE WHEN last_login > NOW() - INTERVAL '7 days' THEN 1 END) as weekly_active
                FROM users
                GROUP BY role
            `);
            
            // 동아리 신청 통계
            const applicationStats = await this.pool.query(`
                SELECT 
                    status,
                    COUNT(*) as count,
                    COUNT(DISTINCT user_id) as unique_users,
                    COUNT(DISTINCT club_id) as unique_clubs
                FROM applications
                GROUP BY status
            `);
            
            // 인기 동아리 Top 5
            const popularClubs = await this.pool.query(`
                SELECT 
                    c.name,
                    c.teacher,
                    COUNT(a.id) as application_count,
                    c.max_capacity,
                    ROUND((COUNT(a.id)::float / c.max_capacity) * 100, 2) as competition_rate
                FROM clubs c
                LEFT JOIN applications a ON c.id = a.club_id
                GROUP BY c.id, c.name, c.teacher, c.max_capacity
                ORDER BY application_count DESC
                LIMIT 5
            `);
            
            // 데이터 정합성 체크
            const integrityCheck = await this.pool.query('SELECT * FROM check_data_integrity()');
            
            return {
                user_statistics: userStats.rows,
                application_statistics: applicationStats.rows,
                popular_clubs: popularClubs.rows,
                data_integrity: integrityCheck.rows,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            return {
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }

    getSystemResources() {
        const memoryUsage = process.memoryUsage();
        const cpuUsage = process.cpuUsage();
        
        return {
            memory: {
                rss: Math.round(memoryUsage.rss / 1024 / 1024), // MB
                heap_used: Math.round(memoryUsage.heapUsed / 1024 / 1024),
                heap_total: Math.round(memoryUsage.heapTotal / 1024 / 1024),
                external: Math.round(memoryUsage.external / 1024 / 1024)
            },
            cpu: {
                user: cpuUsage.user,
                system: cpuUsage.system
            },
            uptime: Math.round(process.uptime()),
            node_version: process.version,
            platform: process.platform,
            timestamp: new Date().toISOString()
        };
    }

    async generateAlert(type, message, severity = 'warning') {
        const alert = {
            id: Date.now(),
            type,
            message,
            severity,
            timestamp: new Date().toISOString()
        };
        
        this.metrics.alerts.push(alert);
        
        // 최근 100개 알림만 유지
        if (this.metrics.alerts.length > 100) {
            this.metrics.alerts = this.metrics.alerts.slice(-100);
        }
        
        console.log(`[${severity.toUpperCase()}] ${type}: ${message}`);
        
        // 심각한 알림은 별도 로깅
        if (severity === 'critical') {
            await this.saveCriticalAlert(alert);
        }
        
        return alert;
    }

    async saveCriticalAlert(alert) {
        try {
            const alertsDir = path.join(__dirname, '..', 'logs');
            await fs.mkdir(alertsDir, { recursive: true });
            
            const filename = path.join(alertsDir, `critical-alerts-${new Date().toISOString().split('T')[0]}.json`);
            
            let existingAlerts = [];
            try {
                const data = await fs.readFile(filename, 'utf8');
                existingAlerts = JSON.parse(data);
            } catch (error) {
                // 파일이 없으면 새로 생성
            }
            
            existingAlerts.push(alert);
            await fs.writeFile(filename, JSON.stringify(existingAlerts, null, 2));
            
        } catch (error) {
            console.error('Critical alert 저장 실패:', error.message);
        }
    }

    async checkThresholds(metrics) {
        const alerts = [];
        
        // 메모리 사용량 체크
        if (metrics.system.memory.heap_used > this.thresholds.maxMemoryUsage) {
            alerts.push(await this.generateAlert(
                'high_memory_usage',
                `메모리 사용량이 임계값을 초과했습니다: ${metrics.system.memory.heap_used}MB > ${this.thresholds.maxMemoryUsage}MB`,
                'warning'
            ));
        }
        
        // 데이터베이스 연결 수 체크
        if (metrics.database.active_connections > this.thresholds.maxDbConnections) {
            alerts.push(await this.generateAlert(
                'high_db_connections',
                `데이터베이스 연결 수가 임계값을 초과했습니다: ${metrics.database.active_connections} > ${this.thresholds.maxDbConnections}`,
                'warning'
            ));
        }
        
        // 응답 시간 체크
        if (metrics.database.connection_time > this.thresholds.maxResponseTime) {
            alerts.push(await this.generateAlert(
                'slow_database_response',
                `데이터베이스 응답 시간이 느립니다: ${metrics.database.connection_time}ms > ${this.thresholds.maxResponseTime}ms`,
                'warning'
            ));
        }
        
        // 데이터베이스 오류 체크
        if (metrics.database.status === 'error') {
            alerts.push(await this.generateAlert(
                'database_error',
                `데이터베이스 연결 오류: ${metrics.database.error}`,
                'critical'
            ));
        }
        
        // 데이터 정합성 체크
        if (metrics.application && metrics.application.data_integrity) {
            const failedChecks = metrics.application.data_integrity.filter(check => check.status === 'FAIL');
            for (const check of failedChecks) {
                alerts.push(await this.generateAlert(
                    'data_integrity_violation',
                    `데이터 정합성 문제: ${check.check_name} - ${check.details}`,
                    'critical'
                ));
            }
        }
        
        return alerts;
    }

    async runFullCheck() {
        console.log('시스템 모니터링 시작...');
        
        const checkStart = Date.now();
        
        try {
            // 각종 메트릭 수집
            const [databaseHealth, applicationMetrics, systemResources] = await Promise.all([
                this.checkDatabaseHealth(),
                this.checkApplicationMetrics(),
                Promise.resolve(this.getSystemResources())
            ]);
            
            const metrics = {
                database: databaseHealth,
                application: applicationMetrics,
                system: systemResources,
                check_duration: Date.now() - checkStart,
                timestamp: new Date().toISOString()
            };
            
            // 임계값 체크 및 알림 생성
            const alerts = await this.checkThresholds(metrics);
            
            // 메트릭 저장
            this.metrics.lastCheck = metrics;
            this.metrics.performance = {
                ...this.metrics.performance,
                [new Date().toISOString()]: {
                    db_response_time: databaseHealth.connection_time,
                    memory_usage: systemResources.memory.heap_used,
                    active_connections: databaseHealth.active_connections
                }
            };
            
            // 성능 히스토리는 최근 24시간만 유지
            const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
            for (const timestamp in this.metrics.performance) {
                if (timestamp < oneDayAgo) {
                    delete this.metrics.performance[timestamp];
                }
            }
            
            console.log(`모니터링 완료 (${Date.now() - checkStart}ms)`);
            console.log(`- 데이터베이스: ${databaseHealth.status}`);
            console.log(`- 메모리 사용량: ${systemResources.memory.heap_used}MB`);
            console.log(`- 활성 연결: ${databaseHealth.active_connections}개`);
            
            if (alerts.length > 0) {
                console.log(`- 새로운 알림: ${alerts.length}개`);
            }
            
            return {
                status: 'success',
                metrics,
                alerts,
                summary: {
                    database_healthy: databaseHealth.status === 'healthy',
                    memory_usage_mb: systemResources.memory.heap_used,
                    active_db_connections: databaseHealth.active_connections,
                    new_alerts: alerts.length
                }
            };
            
        } catch (error) {
            console.error('모니터링 실행 중 오류:', error.message);
            
            await this.generateAlert(
                'monitoring_error',
                `모니터링 시스템 오류: ${error.message}`,
                'critical'
            );
            
            return {
                status: 'error',
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }

    async getStatus() {
        return {
            last_check: this.metrics.lastCheck,
            recent_alerts: this.metrics.alerts.slice(-10),
            performance_trend: Object.keys(this.metrics.performance).slice(-20).map(timestamp => ({
                timestamp,
                ...this.metrics.performance[timestamp]
            })),
            thresholds: this.thresholds
        };
    }

    async cleanup() {
        await this.pool.end();
    }
}

// 스크립트로 실행될 때
if (require.main === module) {
    const monitor = new SystemMonitor();
    
    monitor.runFullCheck()
        .then(result => {
            console.log('\n모니터링 결과:', JSON.stringify(result.summary, null, 2));
            process.exit(result.status === 'success' ? 0 : 1);
        })
        .catch(error => {
            console.error('모니터링 실패:', error);
            process.exit(1);
        })
        .finally(() => {
            monitor.cleanup();
        });
}

module.exports = SystemMonitor;
