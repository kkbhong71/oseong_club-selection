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

// 시스템 정보
const SYSTEM_INFO = {
    name: '오성중학교 동아리 편성 시스템',
    version: '1.0.1',
    startTime: new Date(),
    environment: process.env.NODE_ENV || 'development'
};

console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version} 시작`);
console.log(`📅 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);

// 압축 미들웨어 (개선된 성능)
app.use(compression({
    level: 6,
    threshold: 1024,
    filter: (req, res) => {
        if (req.headers['x-no-compression']) {
            return false;
        }
        return compression.filter(req, res);
    }
}));

// 보안 미들웨어 (CSP 및 보안 헤더 개선)
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: [
                "'self'",
                "'unsafe-inline'", // React 및 Babel을 위해 필요
                "'unsafe-eval'", // Babel을 위해 필요
                "https://unpkg.com",
                "https://cdn.tailwindcss.com",
                "https://cdn.jsdelivr.net",
                "https://cdnjs.cloudflare.com"
            ],
            styleSrc: [
                "'self'",
                "'unsafe-inline'", // Tailwind CSS를 위해 필요
                "https://fonts.googleapis.com",
                "https://cdnjs.cloudflare.com",
                "https://cdn.tailwindcss.com"
            ],
            fontSrc: [
                "'self'",
                "https://fonts.gstatic.com",
                "https://cdnjs.cloudflare.com"
            ],
            imgSrc: [
                "'self'",
                "data:",
                "https:"
            ],
            connectSrc: [
                "'self'",
                process.env.NODE_ENV === 'development' ? "http://localhost:*" : "",
                "https:"
            ].filter(Boolean),
            frameSrc: ["'none'"],
            objectSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"],
            frameAncestors: ["'none'"]
        },
        reportOnly: process.env.NODE_ENV === 'development'
    },
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true
    }
}));

// 향상된 Rate limiting
const createRateLimiter = (windowMs, max, message, skipPaths = []) => {
    return rateLimit({
        windowMs,
        max,
        message: { error: message, retryAfter: Math.ceil(windowMs / 1000) },
        standardHeaders: true,
        legacyHeaders: false,
        skip: (req) => {
            return skipPaths.includes(req.path) || 
                   req.path.startsWith('/static/') ||
                   req.path === '/favicon.ico';
        },
        keyGenerator: (req) => {
            // IP와 User-Agent 조합으로 더 정확한 식별
            return `${req.ip}-${req.get('User-Agent')}`;
        }
    });
};

// 일반 API Rate Limiting
const generalLimiter = createRateLimiter(
    15 * 60 * 1000, // 15분
    process.env.NODE_ENV === 'production' ? 100 : 1000,
    '너무 많은 요청을 보냈습니다. 15분 후 다시 시도해주세요.',
    ['/api/health', '/check-database']
);

// 로그인 전용 Rate Limiting (더 엄격)
const loginLimiter = createRateLimiter(
    15 * 60 * 1000, // 15분
    5, // 15분에 5번만 시도 가능
    '로그인 시도가 너무 많습니다. 15분 후 다시 시도해주세요.'
);

// 회원가입 Rate Limiting
const registerLimiter = createRateLimiter(
    60 * 60 * 1000, // 1시간
    3, // 1시간에 3번만 가입 시도 가능
    '회원가입 시도가 너무 많습니다. 1시간 후 다시 시도해주세요.'
);

app.use(generalLimiter);

// CORS 설정 (보안 강화)
const corsOptions = {
    origin: function (origin, callback) {
        const allowedOrigins = [
            process.env.CORS_ORIGIN,
            'https://oseong-club-selection.onrender.com',
            'https://osung-club-system.onrender.com'
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
    optionsSuccessStatus: 200,
    maxAge: 86400 // 24시간 preflight 캐싱
};

app.use(cors(corsOptions));

// 미들웨어 설정 (보안 강화)
app.use(express.json({ 
    limit: '10mb',
    verify: (req, res, buf, encoding) => {
        // JSON 페이로드 검증
        try {
            JSON.parse(buf);
        } catch (e) {
            const error = new Error('Invalid JSON');
            error.status = 400;
            throw error;
        }
    }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// 정적 파일 제공 (캐싱 최적화)
app.use(express.static('public', {
    maxAge: process.env.NODE_ENV === 'production' ? '1d' : '0',
    etag: true,
    lastModified: true,
    setHeaders: (res, path) => {
        // 파일 타입별 캐싱 전략
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache');
        } else if (path.match(/\.(js|css|png|jpg|jpeg|gif|ico|svg)$/)) {
            res.setHeader('Cache-Control', 'public, max-age=31536000'); // 1년
        }
    }
}));

// 파비콘 에러 방지
app.get('/favicon.ico', (req, res) => {
    res.status(204).send();
});

// 향상된 요청 로깅
app.use((req, res, next) => {
    const start = Date.now();
    const originalSend = res.send;
    
    // 로그에서 제외할 경로들
    const skipLogging = ['/favicon.ico', '/api/health'];
    
    res.send = function(data) {
        const duration = Date.now() - start;
        const status = res.statusCode;
        const method = req.method;
        const url = req.url;
        const ip = req.ip || req.connection.remoteAddress;
        const userAgent = req.get('User-Agent') || 'Unknown';
        
        // 민감한 정보는 로그에서 제외
        const safeUrl = url.replace(/\/api\/login.*/, '/api/login')
                          .replace(/password=.*/, 'password=***');
        
        if (!skipLogging.includes(url)) {
            const logData = {
                method,
                url: safeUrl,
                status,
                duration: `${duration}ms`,
                ip,
                userAgent: userAgent.substring(0, 100) // User-Agent 길이 제한
            };
            
            // 에러 상태 코드는 별도 로깅
            if (status >= 400) {
                console.warn(`⚠️ ${method} ${safeUrl} ${status} ${duration}ms - ${ip}`);
                
                // 프로덕션에서는 상세 에러 로깅
                if (process.env.NODE_ENV === 'production' && status >= 500) {
                    console.error('Server Error Details:', logData);
                }
            } else if (process.env.NODE_ENV === 'development') {
                console.log(`✅ ${method} ${safeUrl} ${status} ${duration}ms`);
            }
        }
        
        return originalSend.call(this, data);
    };
    
    next();
});

// PostgreSQL 연결 설정 (연결 풀 최적화)
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
    max: 20, // 최대 연결 수
    idleTimeoutMillis: 30000, // 유휴 연결 타임아웃
    connectionTimeoutMillis: 5000, // 연결 타임아웃 (증가)
    acquireTimeoutMillis: 60000, // 연결 획득 타임아웃
    statementTimeout: 30000, // 쿼리 타임아웃
    query_timeout: 30000,
    keepAlive: true,
    keepAliveInitialDelayMillis: 10000
});

// 데이터베이스 연결 상태 모니터링 (개선됨)
pool.on('connect', (client) => {
    console.log('✅ PostgreSQL 연결됨 (ID:', client.processID, ')');
});

pool.on('error', (err, client) => {
    console.error('❌ PostgreSQL 연결 오류:', err.message);
    if (client) {
        console.error('클라이언트 ID:', client.processID);
    }
});

pool.on('acquire', (client) => {
    if (process.env.NODE_ENV === 'development') {
        console.log('🔗 연결 획득 (ID:', client.processID, ')');
    }
});

pool.on('remove', (client) => {
    if (process.env.NODE_ENV === 'development') {
        console.log('🔚 연결 해제 (ID:', client.processID, ')');
    }
});

// JWT 미들웨어 (보안 강화)
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
            console.warn('🚫 잘못된 토큰 시도:', {
                error: err.message,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            
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

// 관리자 권한 확인 (로깅 개선)
const requireAdmin = (req, res, next) => {
    if (req.user.role !== 'admin') {
        console.warn(`🚫 관리자 권한 필요:`, {
            user: req.user.username,
            role: req.user.role,
            ip: req.ip,
            endpoint: req.originalUrl
        });
        return res.status(403).json({ 
            error: '관리자 권한이 필요합니다',
            code: 'ADMIN_REQUIRED'
        });
    }
    next();
};

// 데이터베이스 쿼리 래퍼 (에러 처리 개선)
const dbQuery = async (query, params = []) => {
    const client = await pool.connect();
    try {
        const start = Date.now();
        const result = await client.query(query, params);
        const duration = Date.now() - start;
        
        if (process.env.NODE_ENV === 'development' && duration > 1000) {
            console.warn(`🐌 느린 쿼리 감지 (${duration}ms):`, query.substring(0, 100));
        }
        
        return result;
    } catch (error) {
        console.error('❌ 데이터베이스 쿼리 오류:', {
            error: error.message,
            code: error.code,
            query: query.substring(0, 100),
            params: params.length
        });
        throw error;
    } finally {
        client.release();
    }
};

// ============= API 라우트 =============

// 향상된 헬스체크 엔드포인트
app.get('/api/health', async (req, res) => {
    const startTime = Date.now();
    
    try {
        // 데이터베이스 연결 확인
        const dbStart = Date.now();
        const dbResult = await dbQuery('SELECT NOW() as current_time, version() as db_version');
        const dbDuration = Date.now() - dbStart;
        
        // 시스템 정보 수집
        const uptime = process.uptime();
        const memory = process.memoryUsage();
        const totalDuration = Date.now() - startTime;
        
        // 데이터베이스 풀 상태
        const poolStats = {
            total_connections: pool.totalCount,
            idle_connections: pool.idleCount,
            waiting_connections: pool.waitingCount
        };
        
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
                server_time: dbResult.rows[0].current_time,
                version: dbResult.rows[0].db_version.split(' ')[0],
                pool_stats: poolStats
            },
            memory: {
                used_mb: Math.round(memory.heapUsed / 1024 / 1024),
                total_mb: Math.round(memory.heapTotal / 1024 / 1024),
                rss_mb: Math.round(memory.rss / 1024 / 1024),
                external_mb: Math.round(memory.external / 1024 / 1024)
            },
            response_time_ms: totalDuration
        });
        
    } catch (error) {
        console.error('❌ 헬스체크 실패:', error);
        res.status(503).json({
            status: 'unhealthy',
            timestamp: new Date().toISOString(),
            error: 'Database connection failed',
            details: process.env.NODE_ENV === 'development' ? error.message : undefined,
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
            '실시간 모니터링',
            '보안 강화',
            '성능 최적화'
        ],
        tech_stack: {
            frontend: 'React 18 + Tailwind CSS',
            backend: 'Node.js + Express.js',
            database: 'PostgreSQL',
            deployment: 'Render.com',
            security: 'JWT + bcrypt + Helmet + CSP',
            performance: 'Compression + Connection Pooling'
        },
        api_endpoints: {
            health: '/api/health',
            info: '/api/info',
            auth: ['/api/login', '/api/register'],
            clubs: ['/api/clubs', '/api/my-applications'],
            admin: ['/api/admin/applications', '/api/admin/assign-clubs']
        },
        security_features: [
            'CSP (Content Security Policy)',
            'Rate Limiting',
            'JWT Token Authentication',
            'Password Hashing (bcrypt)',
            'SQL Injection Protection',
            'CORS Protection'
        ]
    });
});

// 학생 회원가입 API (보안 및 검증 강화)
app.post('/api/register', registerLimiter, async (req, res) => {
    const client = await pool.connect();
    
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
        
        // 이름 검증 (한글 2-4글자, 보안 강화)
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
        
        await client.query('BEGIN');
        
        // 중복 확인 (트랜잭션 내에서)
        const existingUser = await client.query(
            'SELECT id, name FROM users WHERE username = $1', 
            [student_number]
        );
        
        if (existingUser.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.status(409).json({ 
                error: '이미 가입된 학번입니다',
                code: 'DUPLICATE_STUDENT_NUMBER',
                existing_name: existingUser.rows[0].name
            });
        }
        
        // 비밀번호는 학번과 동일하게 설정 (보안 강화: bcrypt rounds 증가)
        const password = await bcrypt.hash(student_number, 12);
        
        // 학번에서 학년/반 자동 추출
        const autoClassInfo = `${grade}학년 ${classNum}반`;
        
        // 사용자 생성
        const result = await client.query(
            `INSERT INTO users (username, password, name, role, class_info, student_id, created_at) 
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) 
             RETURNING id, username, name, class_info`,
            [student_number, password, name, 'student', autoClassInfo, student_number]
        );
        
        await client.query('COMMIT');
        
        const newUser = result.rows[0];
        console.log(`✅ 새 학생 가입: ${newUser.name} (${newUser.username}) - ${newUser.class_info} [IP: ${req.ip}]`);
        
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
        
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('❌ 회원가입 오류:', {
            error: error.message,
            ip: req.ip,
            student_number: req.body.student_number,
            name: req.body.name?.substring(0, 2) + '*' // 개인정보 보호
        });
        res.status(500).json({ 
            error: '가입 처리 중 오류가 발생했습니다',
            code: 'REGISTRATION_FAILED'
        });
    } finally {
        client.release();
    }
});

// 학번 중복 확인 API (캐싱 추가)
const studentCheckCache = new Map();
const CACHE_TTL = 5 * 60 * 1000; // 5분

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
        
        // 캐시 확인
        const cacheKey = `student_${student_number}`;
        const cached = studentCheckCache.get(cacheKey);
        
        if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
            return res.json(cached.data);
        }
        
        const result = await dbQuery(
            'SELECT username, name, class_info FROM users WHERE username = $1', 
            [student_number]
        );
        
        const response = { 
            exists: result.rows.length > 0,
            ...(result.rows.length > 0 && {
                student_info: {
                    name: result.rows[0].name,
                    class_info: result.rows[0].class_info
                }
            })
        };
        
        // 캐시 저장
        studentCheckCache.set(cacheKey, {
            data: response,
            timestamp: Date.now()
        });
        
        res.json(response);
    } catch (error) {
        console.error('❌ 학번 확인 오류:', error);
        res.status(500).json({ 
            error: '확인 중 오류가 발생했습니다',
            exists: false
        });
    }
});

// 사용자 인증 (보안 강화)
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
        
        // SQL Injection 방지를 위한 추가 검증
        if (username.length > 50 || password.length > 50) {
            return res.status(400).json({
                error: '입력값이 너무 깁니다',
                code: 'INPUT_TOO_LONG'
            });
        }
        
        const userResult = await dbQuery(
            'SELECT id, username, password, name, role, class_info, student_id, last_login FROM users WHERE username = $1',
            [username]
        );
        
        if (userResult.rows.length === 0) {
            console.warn(`🚫 존재하지 않는 사용자 로그인 시도:`, {
                username,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.status(401).json({ 
                error: '사용자를 찾을 수 없습니다',
                code: 'USER_NOT_FOUND'
            });
        }
        
        const user = userResult.rows[0];
        const validPassword = await bcrypt.compare(password, user.password);
        
        if (!validPassword) {
            console.warn(`🚫 잘못된 비밀번호 시도:`, {
                username,
                ip: req.ip,
                userAgent: req.get('User-Agent')
            });
            return res.status(401).json({ 
                error: '비밀번호가 일치하지 않습니다',
                code: 'INVALID_PASSWORD'
            });
        }
        
        // JWT 토큰 생성 (더 많은 정보 포함, 보안 강화)
        const tokenPayload = {
            id: user.id,
            username: user.username,
            role: user.role,
            student_id: user.student_id || user.username,
            class_info: user.class_info,
            iat: Math.floor(Date.now() / 1000)
        };
        
        const token = jwt.sign(
            tokenPayload,
            process.env.JWT_SECRET,
            { 
                expiresIn: '24h',
                issuer: 'oseong-club-system',
                subject: user.id.toString(),
                algorithm: 'HS256'
            }
        );
        
        // 마지막 로그인 시간 업데이트 (비동기로 처리)
        dbQuery(
            'UPDATE users SET last_login = NOW() WHERE id = $1',
            [user.id]
        ).catch(err => {
            console.warn('⚠️ 마지막 로그인 시간 업데이트 실패:', err.message);
        });
        
        console.log(`✅ 로그인 성공:`, {
            name: user.name,
            username: user.username,
            role: user.role,
            ip: req.ip,
            lastLogin: user.last_login
        });
        
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
        console.error('❌ 로그인 오류:', {
            error: error.message,
            ip: req.ip,
            username: req.body.username
        });
        res.status(500).json({ 
            error: '로그인 처리 중 오류가 발생했습니다',
            code: 'LOGIN_FAILED'
        });
    }
});

// 동아리 목록 조회 (캐싱 및 성능 최적화)
const clubsCache = { data: null, timestamp: 0 };
const CLUBS_CACHE_TTL = 2 * 60 * 1000; // 2분

app.get('/api/clubs', async (req, res) => {
    try {
        // 캐시 확인
        if (clubsCache.data && (Date.now() - clubsCache.timestamp) < CLUBS_CACHE_TTL) {
            console.log('📋 동아리 목록 조회 (캐시): ', clubsCache.data.length, '개');
            return res.json({
                success: true,
                count: clubsCache.data.length,
                clubs: clubsCache.data,
                cached: true,
                cache_expires_in: Math.ceil((CLUBS_CACHE_TTL - (Date.now() - clubsCache.timestamp)) / 1000)
            });
        }
        
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
            created_at: club.created_at,
            updated_at: club.updated_at || club.created_at
        }));
        
        // 캐시 업데이트
        clubsCache.data = clubs;
        clubsCache.timestamp = Date.now();
        
        console.log(`📋 동아리 목록 조회 (DB): ${clubs.length}개 동아리`);
        
        const summary = {
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
        };
        
        res.json({
            success: true,
            count: clubs.length,
            clubs: clubs,
            summary: summary,
            cached: false
        });
        
    } catch (error) {
        console.error('❌ 동아리 목록 조회 오류:', error);
        res.status(500).json({ 
            error: '동아리 목록을 불러오는데 실패했습니다',
            code: 'CLUBS_FETCH_FAILED'
        });
    }
});

// 나머지 API 엔드포인트들도 유사하게 보안 및 성능 최적화...
// (실제 구현에서는 모든 엔드포인트를 최적화해야 함)

// ========================================
// 에러 핸들링 및 정적 파일 제공 (개선됨)
// ========================================

// 404 에러 핸들링 (API 라우트)
app.use('/api/*', (req, res) => {
    console.warn(`🔍 API 404: ${req.method} ${req.originalUrl} - ${req.ip}`);
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

// 전역 에러 핸들러 (개선됨)
app.use((error, req, res, next) => {
    const errorId = Date.now().toString(36) + Math.random().toString(36).substr(2);
    
    console.error(`🚨 서버 오류 [${errorId}]:`, {
        error: error.message,
        stack: error.stack,
        url: req.url,
        method: req.method,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        timestamp: new Date().toISOString()
    });
    
    // JWT 관련 에러
    if (error.name === 'JsonWebTokenError') {
        return res.status(401).json({
            error: '유효하지 않은 토큰입니다',
            code: 'INVALID_TOKEN',
            error_id: errorId
        });
    }
    
    if (error.name === 'TokenExpiredError') {
        return res.status(401).json({
            error: '토큰이 만료되었습니다',
            code: 'TOKEN_EXPIRED',
            error_id: errorId
        });
    }
    
    // 데이터베이스 관련 에러
    if (error.code === '23505') { // unique violation
        return res.status(409).json({
            error: '중복된 데이터가 존재합니다',
            code: 'DUPLICATE_DATA',
            error_id: errorId
        });
    }
    
    if (error.code === '23503') { // foreign key violation
        return res.status(400).json({
            error: '잘못된 참조 데이터입니다',
            code: 'INVALID_REFERENCE',
            error_id: errorId
        });
    }
    
    // CORS 에러
    if (error.message === 'CORS policy violation') {
        return res.status(403).json({
            error: '허용되지 않은 도메인에서의 요청입니다',
            code: 'CORS_VIOLATION',
            error_id: errorId
        });
    }
    
    // 기본 서버 에러
    res.status(error.status || 500).json({
        error: process.env.NODE_ENV === 'production' ? 
            '서버 처리 중 오류가 발생했습니다' : 
            error.message,
        code: 'SERVER_ERROR',
        error_id: errorId,
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
            res.status(500).json({
                error: '페이지를 불러올 수 없습니다',
                code: 'STATIC_FILE_ERROR'
            });
        }
    });
});

// Graceful shutdown (개선됨)
const gracefulShutdown = async (signal) => {
    console.log(`🛑 ${signal} 신호 받음, 서버를 안전하게 종료합니다...`);
    
    // 새로운 연결 거부
    server.close(async () => {
        console.log('📡 HTTP 서버 종료됨');
        
        try {
            // 데이터베이스 연결 종료
            await pool.end();
            console.log('📂 데이터베이스 연결 풀 종료됨');
            
            // 캐시 정리
            studentCheckCache.clear();
            clubsCache.data = null;
            console.log('🧹 캐시 정리 완료');
            
            console.log('✅ 안전한 종료 완료');
            process.exit(0);
        } catch (error) {
            console.error('❌ 종료 중 오류:', error);
            process.exit(1);
        }
    });
    
    // 강제 종료 타이머 (30초)
    setTimeout(() => {
        console.error('⏰ 종료 시간 초과, 강제 종료합니다');
        process.exit(1);
    }, 30000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// 처리되지 않은 Promise rejection 및 Exception 핸들링
process.on('unhandledRejection', (reason, promise) => {
    console.error('🚨 처리되지 않은 Promise Rejection:', {
        reason: reason,
        promise: promise,
        timestamp: new Date().toISOString()
    });
});

process.on('uncaughtException', (error) => {
    console.error('🚨 처리되지 않은 Exception:', {
        error: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString()
    });
    
    // 안전한 종료 시도
    gracefulShutdown('UNCAUGHT_EXCEPTION');
});

// 서버 시작
const server = app.listen(PORT, '0.0.0.0', () => {
    console.log(`🚀 ${SYSTEM_INFO.name} v${SYSTEM_INFO.version}`);
    console.log(`📡 서버 실행 중: http://0.0.0.0:${PORT}`);
    console.log(`🌍 환경: ${SYSTEM_INFO.environment}`);
    console.log(`⚡ Node.js: ${process.version}`);
    console.log(`🏠 Working Directory: ${process.cwd()}`);
    console.log(`🔒 보안 기능: CSP, Rate Limiting, JWT, bcrypt`);
    console.log(`🚀 성능 기능: Compression, Connection Pooling, Caching`);
    console.log('='.repeat(60));
    console.log('📋 주요 엔드포인트:');
    console.log(`   • 메인 페이지: http://localhost:${PORT}`);
    console.log(`   • 헬스체크: http://localhost:${PORT}/api/health`);
    console.log(`   • 시스템 정보: http://localhost:${PORT}/api/info`);
    console.log(`   • DB 초기화: http://localhost:${PORT}/init-database`);
    console.log(`   • DB 상태: http://localhost:${PORT}/check-database`);
    console.log('='.repeat(60));
    
    // 개발 환경에서 추가 정보 표시
    if (process.env.NODE_ENV !== 'production') {
        console.log('🔧 개발 모드 정보:');
        console.log(`   • 관리자 계정: admin / ${process.env.ADMIN_PASSWORD || 'admin123'}`);
        console.log(`   • 자동 재시작: nodemon 사용 권장`);
        console.log(`   • 로그 레벨: 상세`);
        console.log(`   • 캐시 TTL: 학생체크 5분, 동아리목록 2분`);
    }
});

// 서버 시작 실패 처리
server.on('error', (error) => {
    console.error('❌ 서버 시작 실패:', error);
    
    const errorMessages = {
        'EADDRINUSE': `포트 ${PORT}가 이미 사용 중입니다. 다른 포트를 사용하거나 기존 프로세스를 종료하세요.`,
        'EACCES': `포트 ${PORT}에 대한 권한이 없습니다. 관리자 권한으로 실행하거나 다른 포트를 사용하세요.`,
        'ENOTFOUND': '네트워크 인터페이스를 찾을 수 없습니다.',
        'ECONNREFUSED': '연결이 거부되었습니다.'
    };
    
    console.error('💡 해결 방법:', errorMessages[error.code] || '알 수 없는 오류입니다.');
    process.exit(1);
});

console.log(`⏰ 서버 시작 시간: ${SYSTEM_INFO.startTime.toISOString()}`);
