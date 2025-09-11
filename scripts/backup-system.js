// scripts/backup-system.js
// 자동화된 백업 및 복구 시스템

const { Pool } = require('pg');
const fs = require('fs').promises;
const path = require('path');
const { spawn } = require('child_process');

class BackupManager {
    constructor() {
        this.pool = new Pool({
            connectionString: process.env.DATABASE_URL,
            ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
        });
        
        this.backupDir = path.join(__dirname, '..', 'backups');
        this.maxBackupAge = 30; // 일
        this.maxBackupCount = 50;
    }

    async ensureBackupDirectory() {
        try {
            await fs.mkdir(this.backupDir, { recursive: true });
        } catch (error) {
            console.error('백업 디렉토리 생성 실패:', error.message);
            throw error;
        }
    }

    async createDataBackup() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const backupFile = path.join(this.backupDir, `data-backup-${timestamp}.json`);
        
        try {
            console.log('데이터 백업 시작...');
            
            // 전체 데이터 추출
            const [users, clubs, applications] = await Promise.all([
                this.pool.query('SELECT * FROM users ORDER BY id'),
                this.pool.query('SELECT * FROM clubs ORDER BY id'),
                this.pool.query('SELECT * FROM applications ORDER BY id')
            ]);
            
            // 관계형 데이터를 포함한 상세 정보
            const detailedApplications = await this.pool.query(`
                SELECT 
                    a.*,
                    u.name as student_name,
                    u.username as student_id,
                    u.class_info,
                    c.name as club_name,
                    c.teacher,
                    c.category
                FROM applications a
                JOIN users u ON a.user_id = u.id
                JOIN clubs c ON a.club_id = c.id
                ORDER BY a.id
            `);
            
            // 통계 정보
            const statistics = await this.pool.query(`
                SELECT 
                    'total_users' as metric,
                    COUNT(*) as value
                FROM users
                UNION ALL
                SELECT 
                    'total_clubs' as metric,
                    COUNT(*) as value
                FROM clubs
                UNION ALL
                SELECT 
                    'total_applications' as metric,
                    COUNT(*) as value
                FROM applications
                UNION ALL
                SELECT 
                    'assigned_students' as metric,
                    COUNT(DISTINCT user_id) as value
                FROM applications 
                WHERE status = 'assigned'
            `);
            
            const backupData = {
                metadata: {
                    backup_time: new Date().toISOString(),
                    backup_type: 'full_data',
                    database_version: await this.getDatabaseVersion(),
                    record_counts: {
                        users: users.rows.length,
                        clubs: clubs.rows.length,
                        applications: applications.rows.length
                    }
                },
                tables: {
                    users: users.rows,
                    clubs: clubs.rows,
                    applications: applications.rows
                },
                reports: {
                    detailed_applications: detailedApplications.rows,
                    statistics: statistics.rows
                }
            };
            
            await fs.writeFile(backupFile, JSON.stringify(backupData, null, 2));
            
            console.log(`데이터 백업 완료: ${backupFile}`);
            return {
                success: true,
                file: backupFile,
                size: (await fs.stat(backupFile)).size,
                records: backupData.metadata.record_counts
            };
            
        } catch (error) {
            console.error('데이터 백업 실패:', error.message);
            throw error;
        }
    }

    async createSQLDump() {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const dumpFile = path.join(this.backupDir, `sql-dump-${timestamp}.sql`);
        
        try {
            console.log('SQL 덤프 생성 시작...');
            
            // PostgreSQL URL 파싱
            const dbUrl = new URL(process.env.DATABASE_URL);
            
            return new Promise((resolve, reject) => {
                const pgDump = spawn('pg_dump', [
                    `--host=${dbUrl.hostname}`,
                    `--port=${dbUrl.port || 5432}`,
                    `--username=${dbUrl.username}`,
                    `--dbname=${dbUrl.pathname.slice(1)}`,
                    '--verbose',
                    '--clean',
                    '--no-owner',
                    '--no-privileges',
                    '--file=' + dumpFile
                ], {
                    env: {
                        ...process.env,
                        PGPASSWORD: dbUrl.password
                    }
                });
                
                let errorOutput = '';
                
                pgDump.stderr.on('data', (data) => {
                    errorOutput += data.toString();
                });
                
                pgDump.on('close', async (code) => {
                    if (code === 0) {
                        try {
                            const stats = await fs.stat(dumpFile);
                            console.log(`SQL 덤프 완료: ${dumpFile} (${Math.round(stats.size / 1024)} KB)`);
                            resolve({
                                success: true,
                                file: dumpFile,
                                size: stats.size
                            });
                        } catch (statError) {
                            reject(new Error(`덤프 파일 확인 실패: ${statError.message}`));
                        }
                    } else {
                        reject(new Error(`pg_dump 실패 (코드: ${code}): ${errorOutput}`));
                    }
                });
                
                pgDump.on('error', (error) => {
                    reject(new Error(`pg_dump 실행 오류: ${error.message}`));
                });
            });
            
        } catch (error) {
            console.error('SQL 덤프 생성 실패:', error.message);
            throw error;
        }
    }

    async getDatabaseVersion() {
        try {
            const result = await this.pool.query('SELECT version()');
            return result.rows[0].version;
        } catch (error) {
            return 'Unknown';
        }
    }

    async listBackups() {
        try {
            await this.ensureBackupDirectory();
            const files = await fs.readdir(this.backupDir);
            
            const backups = [];
            for (const file of files) {
                if (file.endsWith('.json') || file.endsWith('.sql')) {
                    const filePath = path.join(this.backupDir, file);
                    const stats = await fs.stat(filePath);
                    
                    backups.push({
                        filename: file,
                        path: filePath,
                        size: stats.size,
                        created: stats.birthtime,
                        modified: stats.mtime,
                        type: file.endsWith('.json') ? 'data' : 'sql',
                        age_days: Math.floor((Date.now() - stats.birthtime.getTime()) / (1000 * 60 * 60 * 24))
                    });
                }
            }
            
            return backups.sort((a, b) => b.created.getTime() - a.created.getTime());
            
        } catch (error) {
            console.error('백업 목록 조회 실패:', error.message);
            return [];
        }
    }

    async cleanupOldBackups() {
        try {
            const backups = await this.listBackups();
            let deletedCount = 0;
            
            for (const backup of backups) {
                const shouldDelete = backup.age_days > this.maxBackupAge || 
                                  backups.indexOf(backup) >= this.maxBackupCount;
                
                if (shouldDelete) {
                    await fs.unlink(backup.path);
                    console.log(`오래된 백업 삭제: ${backup.filename}`);
                    deletedCount++;
                }
            }
            
            return {
                deleted_count: deletedCount,
                remaining_count: backups.length - deletedCount
            };
            
        } catch (error) {
            console.error('백업 정리 실패:', error.message);
            throw error;
        }
    }

    async restoreFromBackup(backupFile) {
        try {
            console.log(`백업 복원 시작: ${backupFile}`);
            
            // 백업 파일 읽기
            const backupContent = await fs.readFile(backupFile, 'utf8');
            const backupData = JSON.parse(backupContent);
            
            if (!backupData.tables || !backupData.metadata) {
                throw new Error('유효하지 않은 백업 파일 형식');
            }
            
            const client = await this.pool.connect();
            
            try {
                await client.query('BEGIN');
                
                // 기존 데이터 삭제 (주의: 모든 데이터가 삭제됩니다)
                console.log('기존 데이터 삭제 중...');
                await client.query('DELETE FROM applications');
                await client.query('DELETE FROM clubs');
                await client.query('DELETE FROM users WHERE role != \'admin\''); // 관리자는 보존
                
                // 시퀀스 초기화
                await client.query('ALTER SEQUENCE users_id_seq RESTART WITH 1');
                await client.query('ALTER SEQUENCE clubs_id_seq RESTART WITH 1');
                await client.query('ALTER SEQUENCE applications_id_seq RESTART WITH 1');
                
                // 데이터 복원
                console.log('데이터 복원 중...');
                
                // 사용자 복원 (관리자 제외)
                const users = backupData.tables.users.filter(user => user.role !== 'admin');
                for (const user of users) {
                    await client.query(
                        `INSERT INTO users (username, password, name, role, class_info, student_id, created_at, last_login) 
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                        [user.username, user.password, user.name, user.role, user.class_info, 
                         user.student_id, user.created_at, user.last_login]
                    );
                }
                
                // 동아리 복원
                for (const club of backupData.tables.clubs) {
                    await client.query(
                        `INSERT INTO clubs (name, teacher, max_capacity, min_members, category, description, 
                                          activities, goals, requirements, meeting_time, location, created_at, updated_at) 
                         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
                        [club.name, club.teacher, club.max_capacity, club.min_members, club.category,
                         club.description, club.activities, club.goals, club.requirements, 
                         club.meeting_time, club.location, club.created_at, club.updated_at]
                    );
                }
                
                // 신청 복원
                for (const application of backupData.tables.applications) {
                    await client.query(
                        `INSERT INTO applications (user_id, club_id, priority, status, applied_at, assigned_at) 
                         VALUES ($1, $2, $3, $4, $5, $6)`,
                        [application.user_id, application.club_id, application.priority, 
                         application.status, application.applied_at, application.assigned_at]
                    );
                }
                
                await client.query('COMMIT');
                
                console.log('백업 복원 완료');
                return {
                    success: true,
                    restored_records: {
                        users: users.length,
                        clubs: backupData.tables.clubs.length,
                        applications: backupData.tables.applications.length
                    },
                    backup_date: backupData.metadata.backup_time
                };
                
            } catch (error) {
                await client.query('ROLLBACK');
                throw error;
            } finally {
                client.release();
            }
            
        } catch (error) {
            console.error('백업 복원 실패:', error.message);
            throw error;
        }
    }

    async createFullBackup() {
        try {
            await this.ensureBackupDirectory();
            
            console.log('전체 백업 시작...');
            
            // 데이터 백업과 SQL 덤프를 병렬로 실행
            const [dataBackup, sqlDump] = await Promise.allSettled([
                this.createDataBackup(),
                this.createSQLDump().catch(error => {
                    console.warn('SQL 덤프 실패 (pg_dump 없음?), 데이터 백업만 진행:', error.message);
                    return { success: false, error: error.message };
                })
            ]);
            
            // 오래된 백업 정리
            const cleanup = await this.cleanupOldBackups();
            
            return {
                success: true,
                data_backup: dataBackup.status === 'fulfilled' ? dataBackup.value : { success: false, error: dataBackup.reason.message },
                sql_dump: sqlDump.status === 'fulfilled' ? sqlDump.value : { success: false, error: sqlDump.reason.message },
                cleanup: cleanup,
                timestamp: new Date().toISOString()
            };
            
        } catch (error) {
            console.error('전체 백업 실패:', error.message);
            throw error;
        }
    }

    async getBackupStatus() {
        const backups = await this.listBackups();
        const latest = backups.length > 0 ? backups[0] : null;
        
        return {
            total_backups: backups.length,
            latest_backup: latest ? {
                filename: latest.filename,
                created: latest.created,
                size: latest.size,
                age_days: latest.age_days
            } : null,
            backup_directory: this.backupDir,
            settings: {
                max_age_days: this.maxBackupAge,
                max_count: this.maxBackupCount
            }
        };
    }

    async cleanup() {
        await this.pool.end();
    }
}

// CLI 실행
if (require.main === module) {
    const command = process.argv[2];
    const backupManager = new BackupManager();
    
    async function runCommand() {
        try {
            switch (command) {
                case 'create':
                    const result = await backupManager.createFullBackup();
                    console.log('백업 결과:', JSON.stringify(result, null, 2));
                    break;
                    
                case 'list':
                    const backups = await backupManager.listBackups();
                    console.log('백업 목록:');
                    backups.forEach(backup => {
                        console.log(`- ${backup.filename} (${Math.round(backup.size / 1024)} KB, ${backup.age_days}일 전)`);
                    });
                    break;
                    
                case 'status':
                    const status = await backupManager.getBackupStatus();
                    console.log('백업 상태:', JSON.stringify(status, null, 2));
                    break;
                    
                case 'cleanup':
                    const cleanup = await backupManager.cleanupOldBackups();
                    console.log(`정리 완료: ${cleanup.deleted_count}개 삭제, ${cleanup.remaining_count}개 유지`);
                    break;
                    
                case 'restore':
                    const backupFile = process.argv[3];
                    if (!backupFile) {
                        console.error('사용법: node backup-system.js restore <백업파일경로>');
                        process.exit(1);
                    }
                    
                    console.log('경고: 이 작업은 현재 데이터를 모두 삭제하고 백업으로 대체합니다.');
                    console.log('계속하려면 5초 내에 Ctrl+C로 취소하세요...');
                    
                    await new Promise(resolve => setTimeout(resolve, 5000));
                    
                    const restoreResult = await backupManager.restoreFromBackup(backupFile);
                    console.log('복원 결과:', JSON.stringify(restoreResult, null, 2));
                    break;
                    
                default:
                    console.log('사용법:');
                    console.log('  node backup-system.js create   - 전체 백업 생성');
                    console.log('  node backup-system.js list     - 백업 목록 조회');
                    console.log('  node backup-system.js status   - 백업 상태 확인');
                    console.log('  node backup-system.js cleanup  - 오래된 백업 정리');
                    console.log('  node backup-system.js restore <파일> - 백업 복원');
                    process.exit(1);
            }
            
        } catch (error) {
            console.error(`명령 실행 실패: ${error.message}`);
            process.exit(1);
        } finally {
            await backupManager.cleanup();
        }
    }
    
    runCommand();
}

module.exports = BackupManager;
