const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 시스템 정보
const SYSTEM_INFO = {
    name: '오성중학교 동아리 편성 시스템',
    version: '1.0.0',
    startTime: new Date(),
    environment: process.env.NODE_ENV || 'development'
};

console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version} 시작`);
console.log(`📅 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);

// 보안 미들웨어
app.use(helmet({
    contentSecurityPolicy: process.env.NODE_ENV === 'production' ? {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'", 
                "'unsafe-inline'", 
                "'unsafe-eval'",
                "https://unpkg.com",
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com",
                "https://cdn.tailwindcss.com"
            ],
            styleSrc: [
                "'self'", 
                "'unsafe-inline'",
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com",
                "https://cdn.tailwindcss.com"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com",
                "https://cdnjs.cloudflare.com"
            ],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"]
        }
    } : false,
    crossOriginEmbedderPolicy: false
}));

// Rate limiting (환경에 따른 차등 적용)
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: process.env.NODE_ENV === 'production' ? 100 : 1000, // 프로덕션: 100회, 개발: 1000회
    message: {
        error: '너무 많은 요청을 보냈습니다. 잠시 후 다시 시도해주세요.',
        retryAfter: 15 * 60 // 15분 후 재시도
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // 헬스체크는 rate limit에서 제외
        return req.path === '/api/health' || req.path === '/check-database';
    }
});
app.use(limiter);

// 로그인 전용 rate limiting (더 엄격)
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 5, // 15분에 5번만 시도 가능
    message: { error: '로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요.' },
    skipSuccessfulRequests: true
});

// CORS 설정 (환경변수 활용)
const corsOptions = {
    origin: function (origin, callback) {
        // 환경변수에서 허용할 오리진 설정
        const allowedOrigins = [
            process.env.CORS_ORIGIN,
            'https://oseong-club-selection.onrender.com',
            'https://oseong-club-system.onrender.com'
        ].filter(Boolean);

        // 개발 환경에서는 localhost 허용
        if (process.env.NODE_ENV !== 'production') {
            allowedOrigins.push('http://localhost:3000', 'http://127.0.0.1:3000');
        }

        // origin이 없는 경우 (같은 도메인) 허용
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.warn(`🚫 CORS 차단: ${origin}`);
            callback(new Error('CORS policy violation'));
        }
    },
    credentials: true,
    optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// 미들웨어 설정
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 정적 파일 제공 (public 폴더)
app.use(express.static('public', {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0', // 프로덕션에서는 1일 캐시
    etag: true
}));

// 파비콘 에러 방지
app.get('/favicon.ico', (req, res) => {
    res.status(204).send();
});

// 요청 로깅 (간단한 버전)
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    res.send = function(data) {
        const duration = Date.now() - start;
        const status = res.statusCode;
        const method = req.method;
        const url = req.url;
        const ip = req.ip || req.connection.remoteAddress;
        
        // 민감한 정보는 로그에서 제외
        const safeUrl = url.replace(/\/api\/login.*/, '/api/login').replace(/password=.*/, 'password=***');
        
        console.log(`${method} ${safeUrl} ${status} ${duration}ms - ${ip}`);
        
        // 에러 상태 코드는 별도 로깅
        if (status >= 400) {
            console.warn(`⚠️ ${method} ${safeUrl} returned ${status} in ${duration}ms`);
        }
        
        return originalSend.call(this, data);
    };
    
    next();
});

// PostgreSQL 연결 설정 (개선됨)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20, // 최대 연결 수
    idleTimeoutMillis: 30000, // 유휴 연결 타임아웃
    connectionTimeoutMillis: 2000, // 연결 타임아웃
});

// 데이터베이스 연결 상태 모니터링
pool.on('connect', () => {
    console.log('✅ PostgreSQL 연결됨');
});

pool.on('error', (err) => {
    console.error('❌ PostgreSQL 연결 오류:', err);
});

// JWT 미들웨어 (개선됨)
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ 
            error: '접근 권한이 없습니다',
            code: 'NO_TOKEN'
        });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) {
            console.warn('🚫 잘못된 토큰 시도:', err.message);
            return res.status(403).json({ 
                error: '유효하지 않은 토큰입니다',
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
        console.warn(`🚫 관리자 권한 필요: 사용자 ${req.user.username} (역할: ${req.user.role})`);
        return res.status(403).json({ 
            error: '관리자 권한이 필요합니다',
            code: 'ADMIN_REQUIRED'
        });
    }
    next();
};

// ============= API 라우트 =============

// 향상된 헬스체크 엔드포인트
app.get('/api/health', async (req, res) => {
    const startTime = Date.now();
    
    try {
        // 데이터베이스 연결 확인
        const dbStart = Date.now();
        const dbResult = await pool.query('SELECT NOW() as current_time');
        const dbDuration = Date.now() - dbStart;
        
        // 시스템 정보 수집
        const uptime = process.uptime();
        const memory = process.memoryUsage();
        const totalDuration = Date.now() - startTime;
        
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
                response_time_ms: dbDuration,
                server_time: dbResult.rows[0].current_time
            },
            memory: {
                used_mb: Math.round(memory.heapUsed / 1024 / 1024),
                total_mb: Math.round(memory.heapTotal / 1024 / 1024),
                rss_mb: Math.round(memory.rss / 1024 / 1024)
            },
            response_time_ms: totalDuration
        });
        
    } catch (error) {
        console.error('❌ 헬스체크 실패:', error);
        res.status(503).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Database connection failed',
            service: SYSTEM_INFO.name,
            version: SYSTEM_INFO.version
        });
    }
});

// 시스템 정보 엔드포인트 (개선됨)
app.get('/api/info', (req, res) => {
    res.json({
        name: SYSTEM_INFO.name,
        version: SYSTEM_INFO.version,
        description: '2025학년도 창체동아리 신청 및 편성 관리 시스템',
        started_at: SYSTEM_INFO.startTime,
        uptime_seconds: Math.floor(process.uptime()),
        environment: SYSTEM_INFO.environment,
        features: [
            '동아리 신청 및 편성',
            '실시간 현황 확인', 
            '자동 배정 시스템',
            '데이터 내보내기',
            '관리자 대시보드',
            '실시간 모니터링'
        ],
        tech_stack: {
            frontend: 'React 18 + Tailwind CSS',
            backend: 'Node.js + Express.js',
            database: 'PostgreSQL',
            deployment: 'Render.com',
            security: 'JWT + bcrypt + Helmet'
        },
        api_endpoints: {
            health: '/api/health',
            info: '/api/info',
            auth: ['/api/login', '/api/register'],
            clubs: ['/api/clubs', '/api/my-applications'],
            admin: ['/api/admin/applications', '/api/admin/assign-clubs']
        }
    });
});

// 학생 회원가입 API (개선됨)
app.post('/api/register', async (req, res) => {
    try {
        const { student_number, name } = req.body;
        
        // 입력 검증 강화
        if (!student_number || !name) {
            return res.status(400).json({ 
                error: '학번과 이름을 모두 입력해주세요',
                code: 'MISSING_FIELDS',
                details: {
                    student_number_required: !student_number,
                    name_required: !name
                }
            });
        }
        
        // 학번 형식 검증 (4자리 숫자)
        if (!/^\d{4}$/.test(student_number)) {
            return res.status(400).json({ 
                error: '학번은 4자리 숫자로 입력해주세요 (예: 1101)',
                code: 'INVALID_STUDENT_NUMBER_FORMAT'
            });
        }
        
        // 이름 검증 (한글 2-4글자)
        if (!/^[가-힣]{2,4}$/.test(name)) {
            return res.status(400).json({ 
                error: '이름은 한글 2-4글자로 입력해주세요',
                code: 'INVALID_NAME_FORMAT'
            });
        }
        
        // 학번 유효성 검사 (1-3학년, 1-9반)
        const grade = parseInt(student_number.charAt(0));
        const classNum = parseInt(student_number.charAt(1));
        
        if (grade < 1 || grade > 3) {
            return res.status(400).json({
                error: '학년은 1-3 사이여야 합니다',
                code: 'INVALID_GRADE'
            });
        }
        
        if (classNum < 1 || classNum > 9) {
            return res.status(400).json({
                error: '반은 1-9 사이여야 합니다', 
                code: 'INVALID_CLASS'
            });
        }
        
        // 중복 확인
        const existingUser = await pool.query('SELECT id, name FROM users WHERE username = $1', [student_number]);
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ 
                error: '이미 가입된 학번입니다',
                code: 'DUPLICATE_STUDENT_NUMBER',
                existing_name: existingUser.rows[0].name
            });
        }
        
        // 비밀번호는 학번과 동일하게 설정
        const password = await bcrypt.hash(student_number, 12); // 보안 강화: rounds 증가
        
        // 학번에서 학년/반 자동 추출
        const autoClassInfo = `${grade}학년 ${classNum}반`;
        
        // 트랜잭션으로 사용자 생성
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            const result = await client.query(
                `INSERT INTO users (username, password, name, role, class_info, student_id, created_at) 
                 VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
                 RETURNING id, username, name, class_info`,
                [student_number, password, name, 'student', autoClassInfo, student_number]
            );
            
            await client.query('COMMIT');
            
            const newUser = result.rows[0];
            console.log(`✅ 새 학생 가입: ${newUser.name} (${newUser.username}) - ${newUser.class_info}`);
            
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
                    password_hint: '비밀번호는 학번과 동일합니다',
                    note: '로그인 시 아이디와 비밀번호 모두 학번을 사용하세요'
                }
            });
            
        } catch (dbError) {
            await client.query('ROLLBACK');
            throw dbError;
        } finally {
            client.release();
        }
        
    } catch (error) {
        console.error('❌ 회원가입 오류:', error);
        res.status(500).json({ 
            error: '가입 처리 중 오류가 발생했습니다',
            code: 'REGISTRATION_FAILED'
        });
    }
});

// 학번 중복 확인 API
app.get('/api/check-student/:student_number', async (req, res) => {
    try {
        const { student_number } = req.params;
        
        // 학번 형식 검증
        if (!/^\d{4}$/.test(student_number)) {
            return res.status(400).json({ 
                error: '올바른 학번 형식이 아닙니다',
                exists: false
            });
        }
        
        const result = await pool.query(
            'SELECT username, name, class_info FROM users WHERE username = $1', 
            [student_number]
        );
        
        res.json({ 
            exists: result.rows.length > 0,
            ...(result.rows.length > 0 && {
                student_info: {
                    name: result.rows[0].name,
                    class_info: result.rows[0].class_info
                }
            })
        });
    } catch (error) {
        console.error('❌ 학번 확인 오류:', error);
        res.status(500).json({ 
            error: '확인 중 오류가 발생했습니다',
            exists: false
        });
    }
});

// 사용자 인증 (개선됨)
app.post('/api/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        
        // 입력 검증
        if (!username || !password) {
            return res.status(400).json({ 
                error: '아이디와 비밀번호를 입력해주세요',
                code: 'MISSING_CREDENTIALS'
            });
        }
        
        const userQuery = 'SELECT * FROM users WHERE username = $1';
        const userResult = await pool.query(userQuery, [username]);
        
        if (userResult.rows.length === 0) {
            console.warn(`🚫 존재하지 않는 사용자 로그인 시도: ${username}`);
            return res.status(401).json({ 
                error: '사용자를 찾을 수 없습니다',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.warn(`🚫 잘못된 비밀번호 시도: ${username}`);
            return res.status(401).json({ 
                error: '비밀번호가 일치하지 않습니다',
                code: 'INVALID_PASSWORD'
            });
        }
        
        // JWT 토큰 생성 (더 많은 정보 포함)
        const tokenPayload = {
            id: user.id,
            username: user.username,
            role: user.role,
            student_id: user.student_id || user.username,
            class_info: user.class_info
        };
        
        const token = jwt.sign(
            tokenPayload,
            process.env.JWT_SECRET,
            { 
                expiresIn: '24h',
                issuer: 'oseong-club-system',
                subject: user.id.toString()
            }
        );
        
        // 마지막 로그인 시간 업데이트
        await pool.query(
            'UPDATE users SET last_login = NOW() WHERE id = $1',
            [user.id]
        );
        
        console.log(`✅ 로그인 성공: ${user.name} (${user.username}) - ${user.role}`);
        
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
                class_info: user.class_info
            }
        });
        
    } catch (error) {
        console.error('❌ 로그인 오류:', error);
        res.status(500).json({ 
            error: '로그인 처리 중 오류가 발생했습니다',
            code: 'LOGIN_FAILED'
        });
    }
});

// 동아리 목록 조회 (개선됨)
app.get('/api/clubs', async (req, res) => {
    try {
        const query = `
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
        `;
        
        const result = await pool.query(query);
        
        // 호환성을 위해 필드명 매핑 및 데이터 정규화
        const clubs = result.rows.map(club => ({
            ...club,
            max_members: club.max_capacity || club.max_members || 30,
            min_members: club.min_members || 5,
            category: club.category || '일반 활동',
            activities: club.activities || club.description || '다양한 활동',
            goals: club.goals || club.requirements || '학생 역량 개발',
            meeting_time: club.meeting_time || '미정',
            location: club.location || '미정',
            // 추가 메타데이터
            created_at: club.created_at,
            updated_at: club.updated_at || club.created_at
        }));
        
        console.log(`📋 동아리 목록 조회: ${clubs.length}개 동아리`);
        
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
            error: '동아리 목록을 불러오는데 실패했습니다',
            code: 'CLUBS_FETCH_FAILED'
        });
    }
});

// 특정 동아리 상세 정보 (개선됨)
app.get('/api/clubs/:id', async (req, res) => {
    try {
        const { id } = req.params;
        
        // ID 유효성 검사
        if (!/^\d+$/.test(id)) {
            return res.status(400).json({
                error: '올바르지 않은 동아리 ID입니다',
                code: 'INVALID_CLUB_ID'
            });
        }
        
        const query = `
            SELECT 
                c.*,
                COALESCE(s.current_members, 0) as current_members,
                COALESCE(s.pending_applications, 0) as pending_applications,
                COALESCE(s.assigned_members, 0) as assigned_members
            FROM clubs c
            LEFT JOIN (
                SELECT 
                    club_id,
                    COUNT(*) as current_members,
                    COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_applications,
                    COUNT(CASE WHEN status = 'assigned' THEN 1 END) as assigned_members
                FROM applications
                WHERE club_id = $1
                GROUP BY club_id
            ) s ON c.id = s.club_id
            WHERE c.id = $1
        `;
        
        const result = await pool.query(query, [id]);
        
        if (result.rows.length === 0) {
            return res.status(404).json({ 
                error: '동아리를 찾을 수 없습니다',
                code: 'CLUB_NOT_FOUND'
            });
        }
        
        const club = result.rows[0];
        console.log(`🔍 동아리 상세 조회: ${club.name} (ID: ${id})`);
        
        res.json({
            success: true,
            club: {
                ...club,
                max_members: club.max_capacity || club.max_members || 30,
                availability_status: club.current_members >= club.max_capacity ? 'full' :
                                   club.current_members >= club.max_capacity * 0.8 ? 'near_full' : 'available'
            }
        });
        
    } catch (error) {
        console.error('❌ 동아리 상세 조회 오류:', error);
        res.status(500).json({ 
            error: '동아리 정보를 불러오는데 실패했습니다',
            code: 'CLUB_DETAIL_FETCH_FAILED'
        });
    }
});

// 학생 동아리 신청 (개선됨)
app.post('/api/apply', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    
    try {
        const { first_choice, second_choice, third_choice } = req.body;
        const user_id = req.user.id;
        
        // 입력 검증
        if (!first_choice) {
            return res.status(400).json({
                error: '1지망은 필수로 선택해야 합니다',
                code: 'FIRST_CHOICE_REQUIRED'
            });
        }
        
        // 중복 선택 확인
        const choices = [first_choice, second_choice, third_choice].filter(Boolean);
        const uniqueChoices = [...new Set(choices)];
        
        if (choices.length !== uniqueChoices.length) {
            return res.status(400).json({
                error: '같은 동아리를 중복으로 선택할 수 없습니다',
                code: 'DUPLICATE_CHOICES'
            });
        }
        
        // 동아리 존재 여부 확인
        const clubIds = choices.join(',');
        const clubCheck = await client.query(
            `SELECT id, name, max_capacity FROM clubs WHERE id = ANY($1::int[])`,
            [choices]
        );
        
        if (clubCheck.rows.length !== choices.length) {
            return res.status(400).json({
                error: '존재하지 않는 동아리가 포함되어 있습니다',
                code: 'INVALID_CLUB_SELECTION'
            });
        }
        
        await client.query('BEGIN');
        
        // 기존 신청 삭제
        const deleteResult = await client.query('DELETE FROM applications WHERE user_id = $1', [user_id]);
        console.log(`🗑️ 기존 신청 삭제: ${deleteResult.rowCount}건 (사용자: ${req.user.username})`);
        
        // 새로운 신청 추가
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
        
        console.log(`✅ 동아리 신청 완료: ${req.user.name} (${req.user.username}) - ${applications.length}개 지망`);
        
        // 신청 결과 반환
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
            error: '동아리 신청에 실패했습니다',
            code: 'APPLICATION_FAILED'
        });
    } finally {
        client.release();
    }
});

// 학생 신청 현황 조회 (개선됨)
app.get('/api/my-applications', authenticateToken, async (req, res) => {
    try {
        const user_id = req.user.id;
        
        const query = `
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
        `;
        
        const result = await pool.query(query, [user_id]);
        
        console.log(`📋 신청 현황 조회: ${req.user.name} (${result.rows.length}건)`);
        
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
            error: '신청 현황을 불러오는데 실패했습니다',
            code: 'MY_APPLICATIONS_FETCH_FAILED'
        });
    }
});

// 관리자: 모든 신청 현황 (개선됨)
app.get('/api/admin/applications', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const { page = 1, limit = 50, status, club_id, grade } = req.query;
        const offset = (page - 1) * limit;
        
        // 동적 WHERE 절 구성
        const conditions = [];
        const params = [];
        let paramCount = 0;
        
        if (status) {
            conditions.push(`a.status = $${++paramCount}`);
            params.push(status);
        }
        
        if (club_id) {
            conditions.push(`a.club_id = $${++paramCount}`);
            params.push(club_id);
        }
        
        if (grade) {
            conditions.push(`LEFT(u.username, 1) = $${++paramCount}`);
            params.push(grade);
        }
        
        const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
        
        const query = `
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
            ${whereClause}
            ORDER BY c.name, a.priority, u.name
            LIMIT $${++paramCount} OFFSET $${++paramCount}
        `;
        
        params.push(limit, offset);
        
        // 총 개수 조회
        const countQuery = `
            SELECT COUNT(*) as total
            FROM applications a
            JOIN users u ON a.user_id = u.id
            JOIN clubs c ON a.club_id = c.id
            ${whereClause}
        `;
        
        const [applications, countResult] = await Promise.all([
            pool.query(query, params),
            pool.query(countQuery, params.slice(0, -2)) // limit, offset 제외
        ]);
        
        const total = parseInt(countResult.rows[0].total);
        const totalPages = Math.ceil(total / limit);
        
        console.log(`📊 관리자 신청 현황 조회: ${applications.rows.length}/${total}건 (페이지 ${page}/${totalPages})`);
        
        res.json({
            success: true,
            applications: applications.rows,
            pagination: {
                current_page: parseInt(page),
                total_pages: totalPages,
                total_items: total,
                items_per_page: parseInt(limit),
                has_next: page < totalPages,
                has_prev: page > 1
            }
        });
        
    } catch (error) {
        console.error('❌ 관리자 신청 현황 조회 오류:', error);
        res.status(500).json({ 
            error: '신청 현황을 불러오는데 실패했습니다',
            code: 'ADMIN_APPLICATIONS_FETCH_FAILED'
        });
    }
});

// 관리자: 동아리 배정 실행 (개선됨)
app.post('/api/admin/assign-clubs', authenticateToken, requireAdmin, async (req, res) => {
    const client = await pool.connect();
    
    try {
        console.log(`🎯 동아리 배정 시작: ${req.user.name} (${req.user.username})`);
        const startTime = Date.now();
        
        await client.query('BEGIN');
        
        // 모든 신청을 pending으로 초기화
        await client.query("UPDATE applications SET status = 'pending'");
        console.log('📄 모든 신청 상태 초기화 완료');
        
        let totalAssigned = 0;
        let totalRejected = 0;
        const assignmentLog = [];
        
        // 1지망부터 3지망까지 순차적으로 배정
        for (let priority = 1; priority <= 3; priority++) {
            console.log(`🔄 ${priority}지망 배정 중...`);
            
            // 해당 우선순위의 미배정 신청자들을 랜덤 순서로 조회
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
                    
                    assignmentLog.push({
                        student_name: app.student_name,
                        student_id: app.student_id,
                        club_name: app.club_name,
                        priority: priority,
                        status: 'assigned'
                    });
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
        console.log(`🎉 동아리 배정 완료: ${totalAssigned}명 배정, ${totalRejected}명 미배정 (${duration}ms)`);
        
        // 배정 결과 통계
        const statsQuery = `
            SELECT 
                c.name as club_name,
                c.max_capacity,
                COUNT(a.user_id) as assigned_count,
                ROUND((COUNT(a.user_id)::float / c.max_capacity) * 100, 1) as fill_rate
            FROM clubs c
            LEFT JOIN applications a ON c.id = a.club_id AND a.status = 'assigned'
            GROUP BY c.id, c.name, c.max_capacity
            ORDER BY assigned_count DESC
        `;
        
        const stats = await client.query(statsQuery);
        
        res.json({
            success: true,
            message: '동아리 배정이 완료되었습니다!',
            summary: {
                total_assigned: totalAssigned,
                total_rejected: totalRejected,
                assignment_duration_ms: duration,
                clubs_statistics: stats.rows
            },
            assignment_log: ENV.isDevelopment ? assignmentLog.slice(0, 10) : undefined // 개발환경에서만 로그 제공
        });
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 동아리 배정 오류:', error);
        res.status(500).json({ 
            error: '동아리 배정에 실패했습니다',
            code: 'CLUB_ASSIGNMENT_FAILED',
            details: error.message
        });
    } finally {
        client.release();
    }
});

// 관리자: 배정 결과 조회 (개선됨)
app.get('/api/admin/assignments', authenticateToken, requireAdmin, async (req, res) => {
    try {
        const query = `
            SELECT 
                c.id as club_id,
                c.name as club_name,
                c.teacher,
                c.location,
                c.category,
                c.max_capacity as max_members,
                c.min_members,
                COUNT(a.user_id) as assigned_count,
                ROUND((COUNT(a.user_id)::float / c.max_capacity) * 100, 1) as fill_percentage,
                string_agg(
                    u.name || ' (' || u.username || ', ' || u.class_info || ')', 
                    ', ' 
                    ORDER BY u.name
                ) as students,
                CASE 
                    WHEN COUNT(a.user_id) < c.min_members THEN 'under_minimum'
                    WHEN COUNT(a.user_id) = c.max_capacity THEN 'full'
                    WHEN COUNT(a.user_id) >= c.max_capacity * 0.8 THEN 'near_full'
                    ELSE 'normal'
                END as status
            FROM clubs c
            LEFT JOIN applications a ON c.id = a.club_id AND a.status = 'assigned'
            LEFT JOIN users u ON a.user_id = u.id
            GROUP BY c.id, c.name, c.teacher, c.location, c.category, c.max_capacity, c.min_members
            ORDER BY c.category, assigned_count DESC, c.name
        `;
        
        const result = await pool.query(query);
        
        // 전체 통계 계산
        const totalCapacity = result.rows.reduce((sum, club) => sum + club.max_members, 0);
        const totalAssigned = result.rows.reduce((sum, club) => sum + parseInt(club.assigned_count), 0);
        const totalClubs = result.rows.length;
        
        const statusBreakdown = result.rows.reduce((acc, club) => {
            acc[club.status] = (acc[club.status] || 0) + 1;
            return acc;
        }, {});
        
        console.log(`📊 관리자 배정 결과 조회: ${totalClubs}개 동아리, ${totalAssigned}/${totalCapacity}명 배정`);
        
        res.json({
            success: true,
            assignments: result.rows,
            summary: {
                total_clubs: totalClubs,
                total_capacity: totalCapacity,
                total_assigned: totalAssigned,
                fill_rate: Math.round((totalAssigned / totalCapacity) * 100),
                status_breakdown: statusBreakdown,
                by_category: result.rows.reduce((acc, club) => {
                    const category = club.category;
                    if (!acc[category]) {
                        acc[category] = { clubs: 0, assigned: 0, capacity: 0 };
                    }
                    acc[category].clubs++;
                    acc[category].assigned += parseInt(club.assigned_count);
                    acc[category].capacity += club.max_members;
                    return acc;
                }, {})
            }
        });
        
    } catch (error) {
        console.error('❌ 배정 결과 조회 오류:', error);
        res.status(500).json({ 
            error: '배정 결과를 불러오는데 실패했습니다',
            code: 'ASSIGNMENTS_FETCH_FAILED'
        });
    }
});

// ========================================
// 데이터베이스 자동 초기화 기능 (개선됨)
// ========================================

// 데이터베이스 초기화 라우트
app.get('/init-database', async (req, res) => {
    // 프로덕션에서는 특별한 키가 필요하도록 보안 강화
    if (process.env.NODE_ENV === 'production' && req.query.key !== process.env.INIT_KEY) {
        return res.status(403).json({
            error: 'Unauthorized database initialization attempt',
            hint: 'Contact administrator for initialization key'
        });
    }
    
    const client = await pool.connect();
    
    try {
        console.log('🚀 데이터베이스 초기화 시작...');
        const startTime = Date.now();
        
        await client.query('BEGIN');
        
        // 1. 테이블 생성 (수정된 스키마)
        const createTablesSQL = `
            -- 기존 테이블 삭제 후 재생성
            DROP TABLE IF EXISTS applications CASCADE;
            DROP TABLE IF EXISTS assignments CASCADE;
            DROP TABLE IF EXISTS clubs CASCADE;
            DROP TABLE IF EXISTS users CASCADE;

            -- 사용자 테이블 생성 (개선됨)
            CREATE TABLE users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                name VARCHAR(100) NOT NULL,
                role VARCHAR(20) DEFAULT 'student' CHECK (role IN ('student', 'admin')),
                class_info VARCHAR(20),
                student_id VARCHAR(20),
                last_login TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- 동아리 테이블 생성 (개선됨)
            CREATE TABLE clubs (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                teacher VARCHAR(100) NOT NULL,
                max_capacity INTEGER DEFAULT 30 CHECK (max_capacity > 0),
                description TEXT,
                requirements TEXT,
                location VARCHAR(100) DEFAULT '미정',
                meeting_time VARCHAR(100) DEFAULT '미정',
                category VARCHAR(50) DEFAULT '일반 활동',
                min_members INTEGER DEFAULT 5 CHECK (min_members > 0),
                activities TEXT,
                goals TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            -- 동아리 신청 테이블 생성 (개선됨)
            CREATE TABLE applications (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
                priority INTEGER CHECK (priority IN (1, 2, 3)),
                status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'rejected')),
                applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, priority),
                UNIQUE(user_id, club_id)
            );

            -- 최종 배정 테이블 생성 (향후 확장용)
            CREATE TABLE assignments (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
                assigned_by INTEGER REFERENCES users(id),
                assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT,
                UNIQUE(user_id)
            );

            -- 인덱스 생성 (성능 최적화)
            CREATE INDEX idx_applications_user_id ON applications(user_id);
            CREATE INDEX idx_applications_club_id ON applications(club_id);
            CREATE INDEX idx_applications_status ON applications(status);
            CREATE INDEX idx_applications_priority ON applications(priority);
            CREATE INDEX idx_users_role ON users(role);
            CREATE INDEX idx_users_username ON users(username);
            CREATE INDEX idx_clubs_category ON clubs(category);

            -- 트리거 생성 (updated_at 자동 업데이트)
            CREATE OR REPLACE FUNCTION update_updated_at_column()
            RETURNS TRIGGER AS $$
            BEGIN
                NEW.updated_at = CURRENT_TIMESTAMP;
                RETURN NEW;
            END;
            $$ language 'plpgsql';

            CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
            
            CREATE TRIGGER update_clubs_updated_at BEFORE UPDATE ON clubs
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
                
            CREATE TRIGGER update_applications_updated_at BEFORE UPDATE ON applications
                FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        `;

        await client.query(createTablesSQL);
        console.log('✅ 테이블 생성 완료');

        // 2. 관리자 계정 생성
        const adminPassword = await bcrypt.hash(process.env.ADMIN_PASSWORD || 'admin123', 12);

        await client.query(
            `INSERT INTO users (username, password, name, role, created_at) 
             VALUES ($1, $2, $3, $4, NOW())`,
            ['admin', adminPassword, '시스템 관리자', 'admin']
        );
        console.log('✅ 관리자 계정 생성 완료');

        // 3. 동아리 데이터 생성 (더 현실적이고 다양한 데이터)
        const clubs = [
            // 체육 활동
            ['축구부', '김체육', 25, '축구를 통한 체력 증진과 팀워크 향상을 목표로 합니다. 기초부터 차근차근 배울 수 있어 초보자도 환영합니다.', '운동을 좋아하고 적극적인 학생', '운동장', '월/수/금 4교시 후 (1시간)', '체육 활동', 11, '축구 기초 기술 연습, 팀 경기, 체력 훈련, 전술 학습', '전국 중학교 축구 대회 참가 및 교내 축구 리그 운영'],
            ['농구부', '박농구', 20, '농구의 기본기부터 고급 기술까지 체계적으로 학습합니다. 팀워크와 개인 기량을 동시에 향상시킬 수 있습니다.', '키가 크고 운동신경이 좋은 학생 우대', '체육관', '화/목 4교시 후 (1시간)', '체육 활동', 10, '농구 기초 기술, 드리블/슛 연습, 팀 전술, 경기 분석', '교내 농구 대회 개최 및 지역 대회 참가'],
            ['배드민턴부', '정라켓', 16, '배드민턴을 통해 순발력과 집중력을 기를 수 있습니다. 개인전과 복식경기 모두 경험할 수 있습니다.', '꾸준함과 인내심을 가진 학생', '체육관 2층', '월/목 4교시 후 (1시간)', '체육 활동', 8, '배드민턴 기초, 서브/스매시 연습, 복식 전략, 경기 규칙 학습', '교내 배드민턴 토너먼트 및 개인별 기량 향상'],
            
            // 학술 활동
            ['과학탐구부', '이과학', 20, '다양한 과학 실험과 탐구 활동을 통해 과학적 사고력을 기릅니다. 실험 설계부터 결과 분석까지 직접 해볼 수 있습니다.', '과학에 관심이 많고 호기심이 강한 학생', '과학실 1실', '화/금 4교시 후 (1시간 30분)', '학술 활동', 8, '과학 실험, 탐구 프로젝트, 과학 논문 작성, 과학 전시회 준비', '지역 과학 경진대회 참가 및 교내 과학 전시회 개최'],
            ['컴퓨터부', '박정보', 18, 'AI 시대에 필요한 프로그래밍 기초부터 웹 개발까지 배울 수 있습니다. 창의적인 아이디어를 코드로 구현해보세요.', '컴퓨터와 프로그래밍에 관심이 있는 학생', '컴퓨터실', '수/금 4교시 후 (2시간)', '학술 활동', 6, '프로그래밍 기초(Python), 웹사이트 제작, 앱 개발 기초, IT 트렌드 학습', '학교 홈페이지 관리 및 교내 프로그래밍 대회 개최'],
            ['영어회화부', '김영어', 22, '원어민 선생님과 함께하는 살아있는 영어 회화 연습! 영어에 대한 자신감을 기를 수 있습니다.', '영어 회화 실력 향상을 원하는 적극적인 학생', '영어교실 A', '화/목 4교시 후 (1시간)', '학술 활동', 10, '영어 프리토킹, 원어민과 대화, 영어 연극, 팝송으로 배우는 영어', '영어 말하기 대회 참가 및 교내 영어 연극 공연'],
            ['독서토론부', '한독서', 25, '다양한 장르의 책을 읽고 토론하며 비판적 사고력을 기릅니다. 독후감 작성과 발표 능력도 향상시킬 수 있습니다.', '책 읽기를 좋아하고 토론을 즐기는 학생', '도서관 세미나실', '수/금 4교시 후 (1시간 30분)', '학술 활동', 8, '독서 토론, 독후감 작성, 저자와의 만남, 북 리뷰 발표', '교내 독서 경연대회 개최 및 독서 신문 발행'],
            
            // 문화예술 활동
            ['미술부', '최미술', 20, '다양한 미술 기법을 배우고 자신만의 작품을 만들어보세요. 그림에 대한 열정이 있다면 누구나 환영합니다.', '그림 그리기를 좋아하고 창의성이 풍부한 학생', '미술실', '월/목 4교시 후 (2시간)', '문화예술 활동', 7, '수채화, 아크릴화, 소묘, 디자인, 만화 그리기', '교내 미술 전시회 개최 및 지역 미술 대회 참가'],
            ['음악부', '송음악', 24, '다양한 악기 연주와 합창을 통해 음악적 감성을 기릅니다. 음악을 사랑하는 마음만 있으면 충분합니다.', '음악을 사랑하고 악기 연주에 관심이 있는 학생', '음악실', '월/금 4교시 후 (1시간 30분)', '문화예술 활동', 10, '합창, 기악 앙상블, 개인 연주, 음악 이론 학습', '교내 음악회 및 지역 문화제 참여'],
            ['댄스부', '이댄스', 18, 'K-POP부터 현대무용까지 다양한 장르의 댄스를 배울 수 있습니다. 몸으로 표현하는 즐거움을 느껴보세요.', '춤에 관심이 많고 끼가 넘치는 학생', '무용실', '화/금 4교시 후 (1시간 30분)', '문화예술 활동', 8, 'K-POP 안무, 현대무용, 창작 안무, 무대 퍼포먼스', '교내 축제 공연 및 댄스 경연대회 참가'],
            ['연극부', '유연극', 15, '연기를 통해 자신을 표현하고 무대 위에서 꿈을 펼쳐보세요. 표현력과 자신감을 기를 수 있습니다.', '연기에 관심이 있고 표현력이 좋은 학생', '시청각실', '수/금 4교시 후 (2시간)', '문화예술 활동', 6, '연기 연습, 대본 분석, 무대 연출, 발성 연습', '교내 연극 공연 및 지역 청소년 연극제 참가'],
            
            // 특별 활동
            ['방송부', '임방송', 12, '아침 방송부터 각종 행사 진행까지! 방송을 통해 학교 소식을 전하고 진행 능력을 기를 수 있습니다.', '목소리가 좋고 진행에 관심이 있는 학생', '방송실', '화/목 점심시간 + 방과 후', '문화예술 활동', 6, '아침 방송, 행사 진행, 인터뷰, 방송 프로그램 제작', '교내 방송 프로그램 제작 및 각종 행사 진행'],
            ['신문부', '김기자', 16, '학교 소식부터 사회 이슈까지 기사를 작성하고 신문을 제작합니다. 글쓰기 실력과 취재 능력을 기를 수 있습니다.', '글쓰기를 좋아하고 호기심이 많은 학생', '신문부실', '수/금 4교시 후 (2시간)', '학술 활동', 5, '기사 작성, 취재 활동, 신문 편집, 인터뷰', '교내 신문 발행 및 청소년 기자 대회 참가'],
            ['봉사부', '나눔이', 30, '지역사회와 함께하는 다양한 봉사 활동을 통해 나눔의 정신을 실천합니다. 따뜻한 마음을 가진 여러분을 기다립니다.', '봉사 정신이 투철하고 남을 도와주기 좋아하는 학생', '봉사부실', '토요일 오전 (월 2회)', '특별 활동', 10, '환경 정화 활동, 독거노인 도움, 지역 아동센터 봉사, 캠페인 활동', '지역사회 봉사 활동 및 봉사활동 인증']
        ];

        for (const [name, teacher, maxCapacity, description, requirements, location, meetingTime, category, minMembers, activities, goals] of clubs) {
            await client.query(
                `INSERT INTO clubs (name, teacher, max_capacity, description, requirements, location, meeting_time, category, min_members, activities, goals, created_at) 
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NOW())`,
                [name, teacher, maxCapacity, description, requirements, location, meetingTime, category, minMembers, activities, goals]
            );
        }
        console.log(`✅ 동아리 데이터 생성 완료 (${clubs.length}개)`);

        await client.query('COMMIT');

        // 4. 완료 상태 확인
        const stats = await client.query(`
            SELECT 'users' as table_name, count(*) as record_count FROM users
            UNION ALL
            SELECT 'clubs' as table_name, count(*) as record_count FROM clubs
            UNION ALL
            SELECT 'applications' as table_name, count(*) as record_count FROM applications
            UNION ALL
            SELECT 'assignments' as table_name, count(*) as record_count FROM assignments
            ORDER BY table_name
        `);

        const duration = Date.now() - startTime;
        console.log(`🎉 데이터베이스 초기화 완료 (${duration}ms)`);
        console.log('📊 데이터베이스 통계:', stats.rows);

        // 5. 성공 응답
        res.json({
            success: true,
            message: '🎉 오성중학교 동아리 시스템 데이터베이스 초기화가 완료되었습니다!',
            statistics: stats.rows,
            details: {
                clubs_created: clubs.length,
                admin_account: {
                    username: 'admin',
                    password: process.env.ADMIN_PASSWORD || 'admin123',
                    note: '프로덕션에서는 반드시 비밀번호를 변경하세요'
                },
                initialization_time_ms: duration
            },
            next_steps: [
                '1. 학생들이 학번과 이름으로 가입',
                '2. 동아리 3순위까지 신청',
                '3. 관리자가 배정 실행',
                '4. 배정 결과 확인'
            ]
        });

    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 데이터베이스 초기화 오류:', error);
        res.status(500).json({
            success: false,
            message: '데이터베이스 초기화 중 오류가 발생했습니다.',
            error: error.message,
            hint: 'Render.com 로그를 확인하시거나 관리자에게 문의하세요.'
        });
    } finally {
        client.release();
    }
});

// 데이터베이스 상태 확인 라우트 (개선됨)
app.get('/check-database', async (req, res) => {
    try {
        // 테이블 존재 여부 확인
        const tableCheck = await pool.query(`
            SELECT table_name, 
                   pg_size_pretty(pg_total_relation_size(quote_ident(table_name))) as size
            FROM information_schema.tables 
            WHERE table_schema = 'public' 
              AND table_type = 'BASE TABLE'
            ORDER BY table_name
        `);
        
        if (tableCheck.rows.length === 0) {
            return res.json({
                success: false,
                message: '데이터베이스 테이블이 생성되지 않았습니다.',
                tables: [],
                hint: '/init-database 엔드포인트를 사용하여 데이터베이스를 초기화하세요.'
            });
        }
        
        // 데이터 통계
        const stats = await pool.query(`
            SELECT 'users' as table_name, count(*) as record_count FROM users
            UNION ALL
            SELECT 'clubs' as table_name, count(*) as record_count FROM clubs
            UNION ALL
            SELECT 'applications' as table_name, count(*) as record_count FROM applications
            UNION ALL
            SELECT 'assignments' as table_name, count(*) as record_count FROM assignments
            ORDER BY table_name
        `);

        // 동아리 카테고리별 통계
        const clubStats = await pool.query(`
            SELECT 
                category,
                COUNT(*) as club_count,
                SUM(max_capacity) as total_capacity
            FROM clubs 
            GROUP BY category 
            ORDER BY category
        `);

        res.json({
            success: true,
            message: '데이터베이스 상태가 정상입니다',
            database_info: {
                tables: tableCheck.rows,
                record_statistics: stats.rows,
                club_categories: clubStats.rows
            },
            system_status: {
                timestamp: new Date().toISOString(),
                uptime_seconds: Math.floor(process.uptime()),
                environment: process.env.NODE_ENV || 'development'
            }
        });
    } catch (error) {
        console.error('❌ 데이터베이스 상태 확인 오류:', error);
        res.status(500).json({
            success: false,
            error: error.message,
            message: '데이터베이스 상태 확인 중 오류가 발생했습니다.',
            hint: 'DATABASE_URL 환경변수와 PostgreSQL 서버 상태를 확인하세요.'
        });
    }
});

// ========================================
// 에러 핸들링 및 정적 파일 제공
// ========================================

// 404 에러 핸들링 (API 라우트)
app.use('/api/*', (req, res) => {
    res.status(404).json({
        error: '요청하신 API 엔드포인트를 찾을 수 없습니다',
        code: 'API_NOT_FOUND',
        requested_path: req.originalUrl,
        available_endpoints: [
            'GET /api/health',
            'GET /api/info', 
            'POST /api/login',
            'POST /api/register',
            'GET /api/clubs',
            'POST /api/apply',
            'GET /api/my-applications'
        ]
    });
});

// 전역 에러 핸들러
app.use((error, req, res, next) => {
    console.error('🚨 서버 오류:', error);
    
    // JWT 관련 에러
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: '유효하지 않은 토큰입니다',
            code: 'INVALID_TOKEN'
        });
    }
    
    if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: '토큰이 만료되었습니다',
            code: 'TOKEN_EXPIRED'
        });
    }
    
    // 데이터베이스 관련 에러
    if (error.code === '23505') { // unique violation
        return res.status(409).json({
            error: '중복된 데이터가 존재합니다',
            code: 'DUPLICATE_DATA'
        });
    }
    
    if (error.code === '23503') { // foreign key violation
        return res.status(400).json({
            error: '잘못된 참조 데이터입니다',
            code: 'INVALID_REFERENCE'
        });
    }
    
    // 기본 서버 에러
    res.status(error.status || 500).json({
        error: process.env.NODE_ENV === 'production' ? 
            '서버 처리 중 오류가 발생했습니다' : 
            error.message,
        code: 'SERVER_ERROR',
        ...(process.env.NODE_ENV !== 'production' && { 
            stack: error.stack,
            details: error 
        })
    });
});

// 정적 파일 제공 (React 앱) - 반드시 마지막에 위치
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'), (err) => {
        if (err) {
            console.error('정적 파일 제공 오류:', err);
            res.status(500).send('서버 오류가 발생했습니다');
        }
    });
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🛑 SIGTERM 신호 받음, 서버를 안전하게 종료합니다...');
    
    // 데이터베이스 연결 종료
    await pool.end();
    console.log('📂 데이터베이스 연결 종료됨');
    
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('\n🛑 SIGINT 신호 받음, 서버를 안전하게 종료합니다...');
    
    await pool.end();
    console.log('📂 데이터베이스 연결 종료됨');
    
    process.exit(0);
});

// 서버 시작
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version}`);
    console.log(`📡 서버 실행 중: http://0.0.0.0:${PORT}`);
    console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);
    console.log(`⚡ Node.js: ${process.version}`);
    console.log(`🏠 Working Directory: ${process.cwd()}`);
    console.log('='.repeat(50));
    console.log('📋 주요 엔드포인트:');
    console.log(`   • 메인 페이지: http://localhost:${PORT}`);
    console.log(`   • 헬스체크: http://localhost:${PORT}/api/health`);
    console.log(`   • 시스템 정보: http://localhost:${PORT}/api/info`);
    console.log(`   • DB 초기화: http://localhost:${PORT}/init-database`);
    console.log(`   • DB 상태: http://localhost:${PORT}/check-database`);
    console.log('='.repeat(50));
    
    // 개발 환경에서 추가 정보 표시
    if (process.env.NODE_ENV !== 'production') {
        console.log('🔧 개발 모드 정보:');
        console.log(`   • 관리자 계정: admin / ${process.env.ADMIN_PASSWORD || 'admin123'}`);
        console.log(`   • 자동 재시작: nodemon 사용 권장`);
        console.log(`   • 로그 레벨: 상세`);
    }
});

// 서버 시작 실패 처리
server.on('error', (error) => {
    console.error('❌ 서버 시작 실패:', error);
    
    if (error.code === 'EADDRINUSE') {
        console.error(`❌ 포트 ${PORT}가 이미 사용 중입니다.`);
        console.error('다른 포트를 사용하거나 기존 프로세스를 종료하세요.');
    } else if (error.code === 'EACCES') {
        console.error(`❌ 포트 ${PORT}에 대한 권한이 없습니다.`);
        console.error('관리자 권한으로 실행하거나 다른 포트를 사용하세요.');
    }
    
    process.exit(1);
});

console.log(`⏰ 서버 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
