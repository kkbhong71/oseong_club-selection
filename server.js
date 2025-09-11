const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
const compression = require('compression');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 환경변수 검증 및 기본값 설정
const config = {
    JWT_SECRET: process.env.JWT_SECRET || 'oseong-middle-school-2025-super-secret-key',
    ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || 'admin123',
    INIT_KEY: process.env.INIT_KEY || 'default-init-key',
    BCRYPT_SALT_ROUNDS: parseInt(process.env.BCRYPT_SALT_ROUNDS) || 12,
    RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
    RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000,
    LOG_LEVEL: process.env.LOG_LEVEL || 'info',
    NODE_ENV: process.env.NODE_ENV || 'development',
    CORS_ORIGIN: process.env.CORS_ORIGIN
};

// 필수 환경변수 검증
if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL 환경변수가 설정되지 않았습니다.');
    process.exit(1);
}

// 시스템 정보
const SYSTEM_INFO = {
    name: '오성중학교 동아리 편성 시스템',
    version: '1.0.4',
    startTime: new Date(),
    environment: config.NODE_ENV
};

console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version} 시작`);
console.log(`📅 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);

// 압축 미들웨어
app.use(compression({
    level: 6,
    threshold: 1024
}));

// 보안 미들웨어 (CSP 완전 비활성화 - React Babel 호환성을 위해)
app.use(helmet({
    contentSecurityPolicy: false,  // CSP 완전 비활성화
    crossOriginEmbedderPolicy: false,
    hsts: config.NODE_ENV === 'production' ? {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    } : false
}));

// Rate limiting 설정
const createRateLimiter = (windowMs, max, message, skipPaths = []) => {
    return rateLimit({
        windowMs: windowMs || config.RATE_LIMIT_WINDOW_MS,
        max: max || config.RATE_LIMIT_MAX_REQUESTS,
        message: { error: message, retryAfter: Math.ceil(windowMs / 1000) },
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => {
            return skipPaths.includes(req.path) || 
                   req.path.startsWith('/static/') ||
                   req.path === '/favicon.ico';
        }
    });
};

const generalLimiter = createRateLimiter(
    config.RATE_LIMIT_WINDOW_MS,
    config.NODE_ENV === 'production' ? config.RATE_LIMIT_MAX_REQUESTS : 1000,
    '너무 많은 요청을 보냈습니다. 15분 후 다시 시도해주세요.',
    ['/api/health', '/check-database', '/init-database']
);

const loginLimiter = createRateLimiter(
    15 * 60 * 1000,
    5,
    '로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요.'
);

const registerLimiter = createRateLimiter(
    60 * 60 * 1000,
    3,
    '회원가입 시도가 너무 많습니다. 1시간 후 다시 시도해주세요.'
);

app.use(generalLimiter);

// CORS 설정
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            config.CORS_ORIGIN,
            'https://oseong-club-selection.onrender.com'
        ].filter(Boolean);

        if (config.NODE_ENV !== 'production') {
            allowedOrigins.push('http://localhost:3000', 'http://127.0.0.1:3000');
        }

        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            callback(new Error('CORS policy violation'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200,
    maxAge: 86400
};

app.use(cors(corsOptions));

// 미들웨어 설정
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 정적 파일 제공
app.use(express.static('public', {
    maxAge: config.NODE_ENV === 'production' ? '1d' : '0',
    etag: true,
    lastModified: true
}));

app.get('/favicon.ico', (req, res) => {
    res.status(204).send();
});

// 로깅 미들웨어
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    const skipLogging = ['/favicon.ico', '/api/health'];
    
    res.send = function(data) {
        const duration = Date.now() - start;
        const status = res.statusCode;
        const method = req.method;
        const url = req.url;
        const ip = req.ip || req.connection.remoteAddress;
        
        if (!skipLogging.includes(url)) {
            if (status >= 400) {
                console.warn(`⚠️ ${method} ${url} ${status} ${duration}ms - ${ip}`);
            } else if (config.LOG_LEVEL === 'debug') {
                console.log(`✅ ${method} ${url} ${status} ${duration}ms`);
            }
        }
        
        return originalSend.call(this, data);
    };
    
    next();
});

// PostgreSQL 연결 설정
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: config.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 5000,
    acquireTimeoutMillis: 60000,
    statementTimeout: 30000,
    query_timeout: 30000,
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000
});

// JWT 미들웨어
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: '접근 권한이 없습니다',
            code: 'NO_TOKEN'
        });
    }

    jwt.verify(token, config.JWT_SECRET, (err, user) => {
        if (err) {
            const errorMessages = {
                'JsonWebTokenError': '유효하지 않은 토큰입니다',
                'TokenExpiredError': '토큰이 만료되었습니다',
                'NotBeforeError': '토큰이 아직 유효하지 않습니다'
            };
            
            return res.status(403).json({ 
                error: errorMessages[err.name] || '토큰 검증에 실패했습니다',
                code: 'INVALID_TOKEN'
            });
        }
        
        req.user = user;
        next();
    });
};

// 관리자 권한 확인
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ 
            error: '관리자 권한이 필요합니다',
            code: 'ADMIN_REQUIRED'
        });
    }
    next();
};

// 데이터베이스 쿼리 래퍼
const dbQuery = async (query, params = []) => {
    const client = await pool.connect();
    try {
        const result = await client.query(query, params);
        return result;
    } catch (error) {
        console.error('❌ 데이터베이스 쿼리 오류:', error.message);
        throw error;
    } finally {
        client.release();
    }
};

// ============= 데이터베이스 초기화 API =============
app.get('/init-database', async (req, res) => {
    const { key } = req.query;
    
    if (key !== config.INIT_KEY) {
        return res.status(403).json({ 
            error: '올바르지 않은 초기화 키입니다',
            code: 'INVALID_INIT_KEY'
        });
    }
    
    const client = await pool.connect();
    
    try {
        console.log('🔄 데이터베이스 초기화 시작...');
        
        await client.query('BEGIN');
        
        // 기존 테이블 삭제
        await client.query('DROP TABLE IF EXISTS applications CASCADE');
        await client.query('DROP TABLE IF EXISTS clubs CASCADE');
        await client.query('DROP TABLE IF EXISTS users CASCADE');
        
        // users 테이블 생성
        await client.query(`
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(100) NOT NULL,
                role VARCHAR(20) DEFAULT 'student',
                class_info VARCHAR(50),
                student_id VARCHAR(10),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        `);
        
        // clubs 테이블 생성
        await client.query(`
            CREATE TABLE clubs (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                teacher VARCHAR(100) NOT NULL,
                max_capacity INTEGER DEFAULT 30,
                min_members INTEGER DEFAULT 5,
                category VARCHAR(50) DEFAULT '일반 활동',
                description TEXT,
                activities TEXT,
                goals TEXT,
                requirements TEXT,
                meeting_time VARCHAR(100),
                location VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // applications 테이블 생성
        await client.query(`
            CREATE TABLE applications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
                priority INTEGER NOT NULL,
                status VARCHAR(20) DEFAULT 'pending',
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_at TIMESTAMP
            )
        `);
        
        // 관리자 계정 생성
        const hashedAdminPassword = await bcrypt.hash(config.ADMIN_PASSWORD, config.BCRYPT_SALT_ROUNDS);
        await client.query(
            'INSERT INTO users (username, password, name, role) VALUES ($1, $2, $3, $4)',
            ['admin', hashedAdminPassword, '시스템 관리자', 'admin']
        );
        
        // 샘플 동아리 데이터 추가
        const clubs = [
            ['축구부', '김철수', 25, 10, '체육 활동', '축구를 통한 체력 증진과 협동심 배양', '축구 경기, 체력 훈련, 팀워크 훈련', '건강한 신체와 협동심 기르기', '체력 및 운동신경', '화요일 7교시', '운동장'],
            ['농구부', '이영희', 20, 8, '체육 활동', '농구를 통한 키 성장과 순발력 향상', '농구 경기, 드리블 연습, 슛 연습', '농구 실력 향상과 신체 발달', '키 150cm 이상', '목요일 7교시', '체육관'],
            ['미술부', '박지연', 30, 5, '예술 활동', '다양한 미술 기법 학습과 창작 활동', '그리기, 만들기, 전시회 준비', '예술적 감성과 창의력 개발', '미술에 대한 관심', '금요일 7교시', '미술실'],
            ['음악부', '최민수', 35, 10, '예술 활동', '합창과 악기 연주를 통한 음악적 재능 개발', '합창, 악기 연주, 발표회 준비', '음악적 소양과 표현력 향상', '음악에 대한 열정', '수요일 7교시', '음악실'],
            ['과학실험부', '정호영', 25, 8, '학술 활동', '과학 실험을 통한 탐구력과 사고력 배양', '실험, 탐구활동, 과학전람회 준비', '과학적 사고력과 탐구정신 기르기', '과학 관련 과목 평균 80점 이상', '월요일 7교시', '과학실'],
            ['독서토론부', '강수진', 20, 6, '학술 활동', '책 읽기와 토론을 통한 사고력 증진', '독서, 토론, 독후감 작성', '독서 습관과 논리적 사고력 기르기', '독서에 대한 관심', '화요일 7교시', '도서관'],
            ['컴퓨터부', '임기웅', 30, 10, '기술 활동', '컴퓨터 활용 능력과 프로그래밍 기초 학습', '프로그래밍, 홈페이지 제작, 컴퓨터 조립', 'IT 기술 습득과 디지털 소양 기르기', '컴퓨터 기초 지식', '목요일 7교시', '컴퓨터실'],
            ['영어회화부', '김나영', 25, 8, '언어 활동', '원어민과의 대화를 통한 영어 실력 향상', '영어 회화, 게임, 영어 연극', '실용적인 영어 회화 능력 기르기', '영어에 대한 관심', '금요일 7교시', '영어전용교실'],
            ['방송부', '서동혁', 15, 5, '미디어 활동', '방송 제작과 아나운싱 기술 습득', '방송 제작, 아나운싱, 영상 편집', '방송 기술과 발표력 기르기', '목소리가 좋고 발표를 좋아하는 학생', '수요일 7교시', '방송실'],
            ['환경보호부', '윤태준', 20, 6, '봉사 활동', '환경 보호 실천과 생태계 보전 활동', '환경 정화, 재활용, 환경 캠페인', '환경 의식과 실천력 기르기', '환경에 대한 관심', '월요일 7교시', '과학실']
        ];
        
        for (const club of clubs) {
            await client.query(
                `INSERT INTO clubs (name, teacher, max_capacity, min_members, category, description, activities, goals, requirements, meeting_time, location) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
                club
            );
        }
        
        await client.query('COMMIT');
        
        console.log('✅ 데이터베이스 초기화 완료');
        
        res.json({
            success: true,
            message: '데이터베이스가 성공적으로 초기화되었습니다!',
            data: {
                tables_created: ['users', 'clubs', 'applications'],
                admin_account: '관리자 계정 생성 완료',
                sample_clubs: clubs.length + '개 동아리 데이터 추가'
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 데이터베이스 초기화 실패:', error);
        res.status(500).json({ 
            error: '데이터베이스 초기화에 실패했습니다',
            details: error.message
        });
    } finally {
        client.release();
    }
});

// 데이터베이스 상태 확인
app.get('/check-database', async (req, res) => {
    try {
        const tableChecks = await Promise.all([
            dbQuery("SELECT COUNT(*) as count FROM information_schema.tables WHERE table_name = 'users'"),
            dbQuery("SELECT COUNT(*) as count FROM information_schema.tables WHERE table_name = 'clubs'"),
            dbQuery("SELECT COUNT(*) as count FROM information_schema.tables WHERE table_name = 'applications'")
        ]);
        
        const [usersTable, clubsTable, applicationsTable] = tableChecks;
        
        const tablesExist = {
            users: parseInt(usersTable.rows[0].count) > 0,
            clubs: parseInt(clubsTable.rows[0].count) > 0,
            applications: parseInt(applicationsTable.rows[0].count) > 0
        };
        
        const allTablesExist = Object.values(tablesExist).every(exists => exists);
        
        let counts = {};
        if (allTablesExist) {
            const countQueries = await Promise.all([
                dbQuery("SELECT COUNT(*) as count FROM users"),
                dbQuery("SELECT COUNT(*) as count FROM clubs"),
                dbQuery("SELECT COUNT(*) as count FROM applications")
            ]);
            
            counts = {
                users: parseInt(countQueries[0].rows[0].count),
                clubs: parseInt(countQueries[1].rows[0].count),
                applications: parseInt(countQueries[2].rows[0].count)
            };
        }
        
        res.json({
            database_status: allTablesExist ? 'ready' : 'needs_initialization',
            tables_exist: tablesExist,
            record_counts: counts,
            initialization_needed: !allTablesExist,
            init_url: !allTablesExist ? `/init-database?key=${config.INIT_KEY}` : null
        });
        
    } catch (error) {
        console.error('❌ 데이터베이스 상태 확인 실패:', error);
        res.status(500).json({ 
            error: '데이터베이스 상태를 확인할 수 없습니다',
            details: error.message
        });
    }
});

// ============= API 라우트 =============

// 헬스체크
app.get('/api/health', async (req, res) => {
    try {
        const dbResult = await dbQuery('SELECT NOW() as current_time');
        const uptime = process.uptime();
        const memory = process.memoryUsage();
        
        res.json({
            status: 'healthy',
            timestamp: new Date().toISOString(),
            service: SYSTEM_INFO.name,
            version: SYSTEM_INFO.version,
            environment: SYSTEM_INFO.environment,
            uptime: {
                seconds: Math.floor(uptime),
                human: `${Math.floor(uptime / 3600)}시간 ${Math.floor((uptime % 3600) / 60)}분`
            },
            database: {
                status: 'connected',
                server_time: dbResult.rows[0].current_time
            },
            memory: {
                used_mb: Math.round(memory.heapUsed / 1024 / 1024),
                total_mb: Math.round(memory.heapTotal / 1024 / 1024),
                rss_mb: Math.round(memory.rss / 1024 / 1024)
            },
            config: {
                cors_origin: config.CORS_ORIGIN,
                rate_limit: config.RATE_LIMIT_MAX_REQUESTS,
                bcrypt_rounds: config.BCRYPT_SALT_ROUNDS,
                log_level: config.LOG_LEVEL,
                csp_disabled: true  // CSP 비활성화 확인용
            }
        });
        
    } catch (error) {
        console.error('❌ 헬스체크 실패:', error);
        res.status(503).json({
            status: 'unhealthy',
            error: 'Database connection failed'
        });
    }
});

// 시스템 정보
app.get('/api/info', (req, res) => {
    res.json({
        name: SYSTEM_INFO.name,
        version: SYSTEM_INFO.version,
        description: '2025학년도 창체동아리 신청 및 편성 관리 시스템',
        started_at: SYSTEM_INFO.startTime,
        uptime_seconds: Math.floor(process.uptime()),
        environment: SYSTEM_INFO.environment,
        config: {
            bcrypt_rounds: config.BCRYPT_SALT_ROUNDS,
            rate_limit_max: config.RATE_LIMIT_MAX_REQUESTS,
            cors_origin: config.CORS_ORIGIN || 'Not set',
            csp_disabled: true
        }
    });
});

// 학생 회원가입
app.post('/api/register', registerLimiter, async (req, res) => {
    const client = await pool.connect();
    
    try {
        const { student_number, name } = req.body;
        
        if (!student_number || !name) {
            return res.status(400).json({ 
                error: '학번과 이름을 모두 입력해주세요',
                code: 'MISSING_FIELDS'
            });
        }
        
        if (!/^\d{4}$/.test(student_number)) {
            return res.status(400).json({ 
                error: '학번은 4자리 숫자로 입력해주세요 (예: 1101)',
                code: 'INVALID_STUDENT_NUMBER_FORMAT'
            });
        }
        
        if (!/^[가-힣]{2,4}$/.test(name)) {
            return res.status(400).json({ 
                error: '이름은 한글 2-4글자로 입력해주세요',
                code: 'INVALID_NAME_FORMAT'
            });
        }
        
        const grade = parseInt(student_number.charAt(0));
        const classNum = parseInt(student_number.charAt(1));
        
        if (grade < 1 || grade > 3) {
            return res.status(400).json({
                error: '학년은 1-3 사이여야 합니다'
            });
        }
        
        if (classNum < 1 || classNum > 9) {
            return res.status(400).json({
                error: '반은 1-9 사이여야 합니다'
            });
        }
        
        await client.query('BEGIN');
        
        const existingUser = await client.query(
            'SELECT id, name FROM users WHERE username = $1', 
            [student_number]
        );
        
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ 
                error: '이미 가입된 학번입니다',
                existing_name: existingUser.rows[0].name
            });
        }
        
        const password = await bcrypt.hash(student_number, config.BCRYPT_SALT_ROUNDS);
        const autoClassInfo = `${grade}학년 ${classNum}반`;
        
        const result = await client.query(
            `INSERT INTO users (username, password, name, role, class_info, student_id, created_at) 
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
             RETURNING id, username, name, class_info`,
            [student_number, password, name, 'student', autoClassInfo, student_number]
        );
        
        await client.query('COMMIT');
        
        const newUser = result.rows[0];
        console.log(`✅ 새 학생 가입: ${newUser.name} (${newUser.username})`);
        
        res.status(201).json({
            success: true,
            message: '가입이 완료되었습니다!',
            user: {
                id: newUser.id,
                username: newUser.username,
                name: newUser.name,
                class_info: newUser.class_info
            },
            login_info: {
                username: student_number,
                password_hint: '비밀번호는 학번과 동일합니다'
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 회원가입 오류:', error);
        res.status(500).json({ 
            error: '가입 처리 중 오류가 발생했습니다'
        });
    } finally {
        client.release();
    }
});

// 로그인
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ 
                error: '아이디와 비밀번호를 입력해주세요'
            });
        }
        
        const userResult = await dbQuery(
            'SELECT id, username, password, name, role, class_info, student_id, last_login FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            return res.status(401).json({ 
                error: '사용자를 찾을 수 없습니다'
            });
        }
        
        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            return res.status(401).json({ 
                error: '비밀번호가 일치하지 않습니다'
            });
        }
        
        const tokenPayload = {
            id: user.id,
            username: user.username,
            role: user.role,
            student_id: user.student_id || user.username,
            class_info: user.class_info
        };
        
        const token = jwt.sign(tokenPayload, config.JWT_SECRET, { expiresIn: '24h' });
        
        // 마지막 로그인 시간 업데이트
        dbQuery('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id])
            .catch(err => console.warn('로그인 시간 업데이트 실패:', err.message));
        
        console.log(`✅ 로그인 성공: ${user.name} (${user.username})`);
        
        res.json({
            success: true,
            message: `환영합니다, ${user.name}님!`,
            token,
            user: {
                id: user.id,
                username: user.username,
                name: user.name,
                role: user.role,
                student_id: user.student_id || user.username,
                class_info: user.class_info,
                last_login: user.last_login
            }
        });
        
    } catch (error) {
        console.error('❌ 로그인 오류:', error);
        res.status(500).json({ 
            error: '로그인 처리 중 오류가 발생했습니다'
        });
    }
});

// 동아리 목록 조회
app.get('/api/clubs', async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT 
                c.*,
                COALESCE(s.current_members, 0) as current_members,
                COALESCE(s.pending_applications, 0) as pending_applications,
                COALESCE(s.assigned_members, 0) as assigned_members,
                (
                    CASE 
                        WHEN COALESCE(s.current_members, 0) >= c.max_capacity THEN 'full'
                        WHEN COALESCE(s.current_members, 0) >= c.max_capacity * 0.8 THEN 'near_full'
                        ELSE 'available'
                    END
                ) as availability_status
            FROM clubs c
            LEFT JOIN (
                SELECT 
                    club_id,
                    COUNT(*) as current_members,
                    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_applications,
                    COUNT(CASE WHEN status = 'assigned' THEN 1 END) as assigned_members
                FROM applications
                GROUP BY club_id
            ) s ON c.id = s.club_id
            ORDER BY c.category, c.name
        `);
        
        const clubs = result.rows.map(club => ({
            ...club,
            max_members: club.max_capacity || 30,
            min_members: club.min_members || 5,
            category: club.category || '일반 활동',
            activities: club.activities || club.description || '다양한 활동',
            goals: club.goals || club.requirements || '학생 역량 개발',
            meeting_time: club.meeting_time || '미정',
            location: club.location || '미정'
        }));
        
        res.json({
            success: true,
            count: clubs.length,
            clubs: clubs,
            summary: {
                total_clubs: clubs.length,
                by_category: clubs.reduce((acc, club) => {
                    acc[club.category] = (acc[club.category] || 0) + 1;
                    return acc;
                }, {}),
                availability: {
                    available: clubs.filter(c => c.availability_status === 'available').length,
                    near_full: clubs.filter(c => c.availability_status === 'near_full').length,
                    full: clubs.filter(c => c.availability_status === 'full').length
                }
            }
        });
        
    } catch (error) {
        console.error('❌ 동아리 목록 조회 오류:', error);
        res.status(500).json({ 
            error: '동아리 목록을 불러오는데 실패했습니다'
        });
    }
});

// 학생 동아리 신청
app.post('/api/apply', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    
    try {
        const { first_choice, second_choice, third_choice } = req.body;
        const user_id = req.user.id;
        
        if (!first_choice) {
            return res.status(400).json({
                error: '1지망은 필수로 선택해야 합니다'
            });
        }
        
        const choices = [first_choice, second_choice, third_choice].filter(Boolean);
        const uniqueChoices = [...new Set(choices)];
        
        if (choices.length !== uniqueChoices.length) {
            return res.status(400).json({
                error: '같은 동아리를 중복으로 선택할 수 없습니다'
            });
        }
        
        const clubCheck = await client.query(
            `SELECT id, name, max_capacity FROM clubs WHERE id = ANY($1::int[])`,
            [choices]
        );
        
        if (clubCheck.rows.length !== choices.length) {
            return res.status(400).json({
                error: '존재하지 않는 동아리가 포함되어 있습니다'
            });
        }
        
        await client.query('BEGIN');
        
        const deleteResult = await client.query('DELETE FROM applications WHERE user_id = $1', [user_id]);
        
        const applications = [
            { club_id: first_choice, priority: 1 },
            { club_id: second_choice, priority: 2 },
            { club_id: third_choice, priority: 3 }
        ].filter(app => app.club_id);
        
        const insertPromises = applications.map(app =>
            client.query(
                `INSERT INTO applications (user_id, club_id, priority, status, applied_at) 
                 VALUES ($1, $2, $3, 'pending', NOW())`,
                [user_id, app.club_id, app.priority]
            )
        );
        
        await Promise.all(insertPromises);
        await client.query('COMMIT');
        
        console.log(`✅ 동아리 신청 완료: ${req.user.name} - ${applications.length}개 지망`);
        
        const appliedClubs = clubCheck.rows.map(club => {
            const priority = applications.find(app => app.club_id === club.id)?.priority;
            return {
                club_id: club.id,
                club_name: club.name,
                priority: priority,
                max_capacity: club.max_capacity
            };
        }).sort((a, b) => a.priority - b.priority);
        
        res.json({
            success: true,
            message: '동아리 신청이 완료되었습니다!',
            applications: appliedClubs,
            applied_at: new Date().toISOString()
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 동아리 신청 오류:', error);
        res.status(500).json({ 
            error: '동아리 신청에 실패했습니다'
        });
    } finally {
        client.release();
    }
});

// 학생 신청 현황 조회
app.get('/api/my-applications', authenticateToken, async (req, res) => {
    try {
        const user_id = req.user.id;
        
        const result = await dbQuery(`
            SELECT 
                a.*,
                c.name as club_name, 
                c.teacher, 
                c.location,
                c.meeting_time,
                c.max_capacity,
                a.priority as preference,
                a.applied_at,
                CASE 
                    WHEN a.status = 'assigned' THEN '배정 완료'
                    WHEN a.status = 'rejected' THEN '배정 탈락'
                    ELSE '배정 대기'
                END as status_text
            FROM applications a
            JOIN clubs c ON a.club_id = c.id
            WHERE a.user_id = $1
            ORDER BY a.priority
        `, [user_id]);
        
        res.json({
            success: true,
            count: result.rows.length,
            applications: result.rows,
            summary: {
                total_applications: result.rows.length,
                status_breakdown: {
                    assigned: result.rows.filter(app => app.status === 'assigned').length,
                    pending: result.rows.filter(app => app.status === 'pending').length,
                    rejected: result.rows.filter(app => app.status === 'rejected').length
                },
                has_assignment: result.rows.some(app => app.status === 'assigned')
            }
        });
        
    } catch (error) {
        console.error('❌ 신청 현황 조회 오류:', error);
        res.status(500).json({ 
            error: '신청 현황을 불러오는데 실패했습니다'
        });
    }
});

// 관리자: 모든 신청 현황
app.get('/api/admin/applications', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const result = await dbQuery(`
            SELECT 
                a.*,
                u.name as student_name,
                u.username as student_id,
                u.class_info,
                c.name as club_name,
                c.teacher,
                c.max_capacity as max_members,
                c.category,
                a.priority as preference,
                a.applied_at
            FROM applications a
            JOIN users u ON a.user_id = u.id
            JOIN clubs c ON a.club_id = c.id
            ORDER BY c.name, a.priority, u.name
        `);
        
        res.json({
            success: true,
            applications: result.rows
        });
        
    } catch (error) {
        console.error('❌ 관리자 신청 현황 조회 오류:', error);
        res.status(500).json({ 
            error: '신청 현황을 불러오는데 실패했습니다'
        });
    }
});

// 관리자: 동아리 배정 실행
app.post('/api/admin/assign-clubs', authenticateToken, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    
    try {
        console.log(`🎯 동아리 배정 시작: ${req.user.name}`);
        const startTime = Date.now();
        
        await client.query('BEGIN');
        
        // 모든 신청을 pending으로 초기화
        await client.query("UPDATE applications SET status = 'pending'");
        
        let totalAssigned = 0;
        let totalRejected = 0;
        
        // 1지망부터 3지망까지 순차적으로 배정
        for (let priority = 1; priority <= 3; priority++) {
            const applications = await client.query(`
                SELECT 
                    a.user_id, 
                    a.club_id, 
                    c.max_capacity,
                    u.name as student_name,
                    u.username as student_id,
                    c.name as club_name,
                    (SELECT COUNT(*) FROM applications a2 WHERE a2.club_id = a.club_id AND a2.status = 'assigned') as current_assigned
                FROM applications a
                JOIN clubs c ON a.club_id = c.id
                JOIN users u ON a.user_id = u.id
                WHERE a.priority = $1 
                  AND a.status = 'pending'
                  AND a.user_id NOT IN (
                      SELECT user_id FROM applications WHERE status = 'assigned'
                  )
                ORDER BY RANDOM()
            `, [priority]);
            
            let assignedInThisPriority = 0;
            
            for (const app of applications.rows) {
                if (app.current_assigned < app.max_capacity) {
                    // 배정 가능
                    await client.query(
                        "UPDATE applications SET status = 'assigned' WHERE user_id = $1 AND club_id = $2",
                        [app.user_id, app.club_id]
                    );
                    
                    // 해당 학생의 다른 지망 신청들을 rejected로 변경
                    await client.query(
                        "UPDATE applications SET status = 'rejected' WHERE user_id = $1 AND club_id != $2",
                        [app.user_id, app.club_id]
                    );
                    
                    assignedInThisPriority++;
                    totalAssigned++;
                }
            }
            
            console.log(`✅ ${priority}지망 배정 완료: ${assignedInThisPriority}명`);
        }
        
        // 최종 미배정자들을 rejected로 처리
        const rejectedResult = await client.query(
            "UPDATE applications SET status = 'rejected' WHERE status = 'pending'"
        );
        totalRejected = rejectedResult.rowCount;
        
        await client.query('COMMIT');
        
        const duration = Date.now() - startTime;
        console.log(`🎉 동아리 배정 완료: ${totalAssigned}명 배정, ${totalRejected}명 미배정`);
        
        res.json({
            success: true,
            message: '동아리 배정이 완료되었습니다!',
            summary: {
                total_assigned: totalAssigned,
                total_rejected: totalRejected,
                assignment_duration_ms: duration
            }
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 동아리 배정 오류:', error);
        res.status(500).json({ 
            error: '동아리 배정에 실패했습니다'
        });
    } finally {
        client.release();
    }
});

// ========================================
// 에러 핸들링 및 정적 파일 제공
// ========================================

// 404 에러 핸들링 (API 라우트)
app.use('/api/*', (req, res) => {
    res.status(404).json({
        error: '요청하신 API 엔드포인트를 찾을 수 없습니다',
        requested_path: req.originalUrl
    });
});

// 전역 에러 핸들러
app.use((error, req, res, next) => {
    console.error('🚨 서버 오류:', error.message);
    
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: '유효하지 않은 토큰입니다'
        });
    }
    
    if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: '토큰이 만료되었습니다'
        });
    }
    
    if (error.message === 'CORS policy violation') {
        return res.status(403).json({
            error: '허용되지 않은 도메인에서의 요청입니다'
        });
    }
    
    res.status(error.status || 500).json({
        error: config.NODE_ENV === 'production' ? 
            '서버 처리 중 오류가 발생했습니다' : 
            error.message
    });
});

// 정적 파일 제공 (React 앱)
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
        if (err) {
            console.error('정적 파일 제공 오류:', err);
            res.status(500).json({
                error: '페이지를 불러올 수 없습니다'
            });
        }
    });
});

// Graceful shutdown
const gracefulShutdown = async (signal) => {
    console.log(`🛑 ${signal} 신호 받음, 서버를 안전하게 종료합니다...`);
    
    server.close(async () => {
        console.log('📡 HTTP 서버 종료됨');
        
        try {
            await pool.end();
            console.log('📂 데이터베이스 연결 풀 종료됨');
            console.log('✅ 안전한 종료 완료');
            process.exit(0);
        } catch (error) {
            console.error('❌ 종료 중 오류:', error);
            process.exit(1);
        }
    });
    
    setTimeout(() => {
        console.error('⏰ 종료 시간 초과, 강제 종료합니다');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// 처리되지 않은 Promise rejection 핸들링
process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 처리되지 않은 Promise Rejection:', reason);
});

process.on('uncaughtException', (error) => {
    console.error('🚨 처리되지 않은 Exception:', error.message);
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// 서버 시작
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version}`);
    console.log(`📡 서버 실행 중: http://0.0.0.0:${PORT}`);
    console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);
    console.log(`🔒 보안 기능: CSP 비활성화 (React 호환), Rate Limiting, JWT, bcrypt`);
    console.log('='.repeat(60));
    console.log('📋 주요 엔드포인트:');
    console.log(`   • 메인 페이지: http://localhost:${PORT}`);
    console.log(`   • 헬스체크: http://localhost:${PORT}/api/health`);
    console.log(`   • DB 초기화: http://localhost:${PORT}/init-database?key=${config.INIT_KEY}`);
    console.log('='.repeat(60));
});

server.on('error', (error) => {
    console.error('❌ 서버 시작 실패:', error);
    process.exit(1);
});

console.log(`⏰ 서버 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
