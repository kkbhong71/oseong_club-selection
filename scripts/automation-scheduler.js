// scripts/automation-scheduler.js
// 시스템 운영 작업 자동화 및 스케줄링

const cron = require('node-cron');
const { Pool } = require('pg');
const SystemMonitor = require('./monitoring');
const BackupManager = require('./backup-system');
const fs = require('fs').promises;
const path = require('path');

class AutomationScheduler {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        this.monitor = new SystemMonitor();
        this.backupManager = new BackupManager();
        this.jobs = new Map();
        
        this.config = {
            monitoring_interval: process.env.MONITORING_INTERVAL || '*/5 * * * *', // 5분마다
            backup_time: process.env.BACKUP_TIME || '0 2 * * *', // 매일 새벽 2시
            cleanup_time: process.env.CLEANUP_TIME || '0 3 * * 0', // 매주 일요일 새벽 3시
            report_time: process.env.REPORT_TIME || '0 9 * * 1', // 매주 월요일 오전 9시
            notification_webhook: process.env.SLACK_WEBHOOK_URL || null
        };
    }

    async initializeScheduler() {
        console.log('자동화 스케줄러 초기화 중...');
        
        // 시스템 모니터링 (5분마다)
        this.scheduleJob('monitoring', this.config.monitoring_interval, async () => {
            await this.runMonitoring();
        });
        
        // 일일 백업 (매일 새벽 2시)
        this.scheduleJob('daily_backup', this.config.backup_time, async () => {
            await this.runDailyBackup();
        });
        
        // 주간 정리 작업 (매주 일요일 새벽 3시)
        this.scheduleJob('weekly_cleanup', this.config.cleanup_time, async () => {
            await this.runWeeklyCleanup();
        });
        
        // 주간 보고서 (매주 월요일 오전 9시)
        this.scheduleJob('weekly_report', this.config.report_time, async () => {
            await this.generateWeeklyReport();
        });
        
        // 동아리 신청 마감 알림 (동적으로 설정)
        await this.scheduleApplicationDeadlines();
        
        console.log('스케줄러 초기화 완료');
        this.listActiveJobs();
    }

    scheduleJob(name, cronExpression, taskFunction) {
        if (this.jobs.has(name)) {
            this.jobs.get(name).destroy();
        }
        
        const task = cron.schedule(cronExpression, async () => {
            console.log(`[${new Date().toISOString()}] 작업 시작: ${name}`);
            
            try {
                await taskFunction();
                console.log(`[${new Date().toISOString()}] 작업 완료: ${name}`);
            } catch (error) {
                console.error(`[${new Date().toISOString()}] 작업 실패: ${name} - ${error.message}`);
                await this.sendNotification(`작업 실패: ${name}`, error.message, 'error');
            }
        }, {
            scheduled: false
        });
        
        this.jobs.set(name, task);
        task.start();
        
        console.log(`작업 등록: ${name} (${cronExpression})`);
    }

    async runMonitoring() {
        const result = await this.monitor.runFullCheck();
        
        if (result.status === 'error' || result.alerts.length > 0) {
            const message = result.status === 'error' ? 
                `모니터링 시스템 오류: ${result.error}` :
                `시스템 알림 ${result.alerts.length}개 발생`;
            
            await this.sendNotification('시스템 모니터링 알림', message, 'warning');
        }
        
        // 성능 지표가 임계값을 초과하는 경우 즉시 알림
        if (result.metrics && result.metrics.system.memory.heap_used > 400) {
            await this.sendNotification(
                '높은 메모리 사용량 감지',
                `현재 메모리 사용량: ${result.metrics.system.memory.heap_used}MB`,
                'warning'
            );
        }
    }

    async runDailyBackup() {
        console.log('일일 백업 시작...');
        
        const result = await this.backupManager.createFullBackup();
        
        if (result.success) {
            const message = `백업 완료\n` +
                `- 데이터 백업: ${result.data_backup.success ? '성공' : '실패'}\n` +
                `- SQL 덤프: ${result.sql_dump.success ? '성공' : '실패'}\n` +
                `- 정리된 파일: ${result.cleanup.deleted_count}개`;
            
            await this.sendNotification('일일 백업 완료', message, 'info');
        } else {
            await this.sendNotification('백업 실패', '일일 백업 중 오류 발생', 'error');
        }
    }

    async runWeeklyCleanup() {
        console.log('주간 정리 작업 시작...');
        
        const tasks = [];
        
        // 오래된 로그 파일 정리
        tasks.push(this.cleanupLogFiles());
        
        // 임시 파일 정리
        tasks.push(this.cleanupTempFiles());
        
        // 데이터베이스 정리
        tasks.push(this.cleanupDatabase());
        
        // 오래된 백업 정리
        tasks.push(this.backupManager.cleanupOldBackups());
        
        const results = await Promise.allSettled(tasks);
        
        const summary = results.map((result, index) => {
            const taskName = ['로그파일', '임시파일', '데이터베이스', '백업파일'][index];
            return `${taskName}: ${result.status === 'fulfilled' ? '성공' : '실패'}`;
        }).join('\n');
        
        await this.sendNotification('주간 정리 작업 완료', summary, 'info');
    }

    async cleanupLogFiles() {
        const logsDir = path.join(__dirname, '..', 'logs');
        
        try {
            const files = await fs.readdir(logsDir).catch(() => []);
            let deletedCount = 0;
            
            for (const file of files) {
                const filePath = path.join(logsDir, file);
                const stats = await fs.stat(filePath);
                const ageInDays = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60 * 24);
                
                if (ageInDays > 30) {
                    await fs.unlink(filePath);
                    deletedCount++;
                }
            }
            
            return { deleted: deletedCount };
        } catch (error) {
            console.error('로그 파일 정리 실패:', error.message);
            throw error;
        }
    }

    async cleanupTempFiles() {
        const tempDirs = ['/tmp', os.tmpdir()];
        let deletedCount = 0;
        
        for (const tempDir of tempDirs) {
            try {
                const files = await fs.readdir(tempDir).catch(() => []);
                
                for (const file of files) {
                    if (file.startsWith('oseong-') || file.startsWith('club-')) {
                        const filePath = path.join(tempDir, file);
                        const stats = await fs.stat(filePath);
                        const ageInHours = (Date.now() - stats.mtime.getTime()) / (1000 * 60 * 60);
                        
                        if (ageInHours > 24) {
                            await fs.unlink(filePath);
                            deletedCount++;
                        }
                    }
                }
            } catch (error) {
                console.warn(`임시 디렉토리 정리 건너뜀: ${tempDir}`);
            }
        }
        
        return { deleted: deletedCount };
    }

    async cleanupDatabase() {
        try {
            // 미사용 세션 정리
            const result = await this.pool.query(`
                SELECT cleanup_old_data() as result
            `);
            
            // 통계 업데이트
            await this.pool.query('ANALYZE');
            
            return { result: result.rows[0].result };
        } catch (error) {
            console.error('데이터베이스 정리 실패:', error.message);
            throw error;
        }
    }

    async generateWeeklyReport() {
        console.log('주간 보고서 생성 중...');
        
        try {
            // 지난 주 통계 수집
            const weekAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
            
            const [userStats, applicationStats, clubStats, systemStats] = await Promise.all([
                this.getUserWeeklyStats(weekAgo),
                this.getApplicationWeeklyStats(weekAgo),
                this.getClubWeeklyStats(),
                this.getSystemWeeklyStats()
            ]);
            
            const report = {
                period: {
                    start: weekAgo.toISOString(),
                    end: new Date().toISOString()
                },
                statistics: {
                    users: userStats,
                    applications: applicationStats,
                    clubs: clubStats,
                    system: systemStats
                },
                generated_at: new Date().toISOString()
            };
            
            // 보고서 파일 저장
            const reportsDir = path.join(__dirname, '..', 'reports');
            await fs.mkdir(reportsDir, { recursive: true });
            
            const reportFile = path.join(reportsDir, `weekly-report-${new Date().toISOString().split('T')[0]}.json`);
            await fs.writeFile(reportFile, JSON.stringify(report, null, 2));
            
            // 요약 메시지 생성
            const summary = `주간 보고서 생성 완료\n` +
                `기간: ${weekAgo.toLocaleDateString('ko-KR')} ~ ${new Date().toLocaleDateString('ko-KR')}\n` +
                `새 가입자: ${userStats.new_users}명\n` +
                `새 신청: ${applicationStats.new_applications}개\n` +
                `시스템 가동률: ${systemStats.uptime_percentage}%`;
            
            await this.sendNotification('주간 보고서', summary, 'info');
            
            return report;
            
        } catch (error) {
            console.error('주간 보고서 생성 실패:', error.message);
            throw error;
        }
    }

    async getUserWeeklyStats(since) {
        const result = await this.pool.query(`
            SELECT 
                COUNT(*) as new_users,
                COUNT(CASE WHEN last_login IS NOT NULL THEN 1 END) as active_users
            FROM users 
            WHERE created_at >= $1 AND role = 'student'
        `, [since]);
        
        return result.rows[0];
    }

    async getApplicationWeeklyStats(since) {
        const result = await this.pool.query(`
            SELECT 
                COUNT(*) as new_applications,
                COUNT(DISTINCT user_id) as unique_applicants,
                COUNT(CASE WHEN status = 'assigned' THEN 1 END) as assigned_count
            FROM applications 
            WHERE applied_at >= $1
        `, [since]);
        
        return result.rows[0];
    }

    async getClubWeeklyStats() {
        const result = await this.pool.query(`
            SELECT 
                c.name,
                COUNT(a.id) as total_applications,
                COUNT(CASE WHEN a.status = 'assigned' THEN 1 END) as assigned_count,
                c.max_capacity,
                ROUND((COUNT(CASE WHEN a.status = 'assigned' THEN 1 END)::float / c.max_capacity) * 100, 2) as fill_rate
            FROM clubs c
            LEFT JOIN applications a ON c.id = a.club_id
            GROUP BY c.id, c.name, c.max_capacity
            ORDER BY total_applications DESC
            LIMIT 5
        `);
        
        return result.rows;
    }

    async getSystemWeeklyStats() {
        // 시스템 가동률 계산 (실제 구현에서는 더 정교한 로직 필요)
        return {
            uptime_percentage: 99.9,
            total_requests: 'N/A',
            average_response_time: 'N/A',
            error_rate: 0.1
        };
    }

    async scheduleApplicationDeadlines() {
        // 동아리 신청 마감일이 설정되어 있다면 알림 스케줄 등록
        // 실제 구현에서는 설정 테이블에서 마감일을 조회해야 함
        
        const deadlineSettings = process.env.APPLICATION_DEADLINE;
        if (deadlineSettings) {
            const deadline = new Date(deadlineSettings);
            const oneDayBefore = new Date(deadline.getTime() - 24 * 60 * 60 * 1000);
            const oneHourBefore = new Date(deadline.getTime() - 60 * 60 * 1000);
            
            // 하루 전 알림
            if (oneDayBefore > new Date()) {
                this.scheduleOneTimeJob('deadline_1day', oneDayBefore, async () => {
                    await this.sendNotification(
                        '동아리 신청 마감 알림',
                        '동아리 신청 마감까지 24시간 남았습니다.',
                        'info'
                    );
                });
            }
            
            // 한 시간 전 알림
            if (oneHourBefore > new Date()) {
                this.scheduleOneTimeJob('deadline_1hour', oneHourBefore, async () => {
                    await this.sendNotification(
                        '동아리 신청 마감 임박',
                        '동아리 신청 마감까지 1시간 남았습니다.',
                        'warning'
                    );
                });
            }
        }
    }

    scheduleOneTimeJob(name, date, taskFunction) {
        const now = new Date();
        const delay = date.getTime() - now.getTime();
        
        if (delay > 0) {
            setTimeout(async () => {
                console.log(`[${new Date().toISOString()}] 일회성 작업 실행: ${name}`);
                try {
                    await taskFunction();
                } catch (error) {
                    console.error(`일회성 작업 실패: ${name} - ${error.message}`);
                }
            }, delay);
            
            console.log(`일회성 작업 예약: ${name} (${date.toISOString()})`);
        }
    }

    async sendNotification(title, message, severity = 'info') {
        const notification = {
            title,
            message,
            severity,
            timestamp: new Date().toISOString(),
            service: '오성중학교 동아리 시스템'
        };
        
        console.log(`[${severity.toUpperCase()}] ${title}: ${message}`);
        
        // Slack 웹훅이 설정되어 있으면 전송
        if (this.config.notification_webhook) {
            try {
                const color = {
                    info: '#36a64f',
                    warning: '#ff9900',
                    error: '#ff0000'
                }[severity] || '#36a64f';
                
                const payload = {
                    attachments: [{
                        color: color,
                        title: `[${notification.service}] ${title}`,
                        text: message,
                        footer: '시스템 알림',
                        ts: Math.floor(Date.now() / 1000)
                    }]
                };
                
                const response = await fetch(this.config.notification_webhook, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                
                if (!response.ok) {
                    console.warn('알림 전송 실패:', response.statusText);
                }
            } catch (error) {
                console.warn('알림 전송 오류:', error.message);
            }
        }
    }

    listActiveJobs() {
        console.log('\n활성 스케줄 작업:');
        for (const [name, task] of this.jobs) {
            console.log(`- ${name}: ${task.getPattern()}`);
        }
    }

    stopAllJobs() {
        console.log('모든 스케줄 작업 중지 중...');
        for (const [name, task] of this.jobs) {
            task.destroy();
            console.log(`작업 중지: ${name}`);
        }
        this.jobs.clear();
    }

    async cleanup() {
        this.stopAllJobs();
        await this.monitor.cleanup();
        await this.backupManager.cleanup();
        await this.pool.end();
    }
}

// 스크립트로 실행될 때
if (require.main === module) {
    const scheduler = new AutomationScheduler();
    
    // 신호 핸들러 등록
    process.on('SIGTERM', async () => {
        console.log('SIGTERM 수신, 정리 작업 시작...');
        await scheduler.cleanup();
        process.exit(0);
    });
    
    process.on('SIGINT', async () => {
        console.log('SIGINT 수신, 정리 작업 시작...');
        await scheduler.cleanup();
        process.exit(0);
    });
    
    // 스케줄러 시작
    scheduler.initializeScheduler()
        .then(() => {
            console.log('자동화 스케줄러가 실행 중입니다...');
            console.log('종료하려면 Ctrl+C를 누르세요.');
        })
        .catch(error => {
            console.error('스케줄러 초기화 실패:', error);
            process.exit(1);
        });
}

module.exports = AutomationScheduler;
