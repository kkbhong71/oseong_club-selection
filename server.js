const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// 보안 미들웨어
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100 // 최대 100회 요청
});
app.use(limiter);

// CORS 설정
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? 
    ['https://your-app.onrender.com'] : 
    ['http://localhost:3000', 'http://127.0.0.1:3000'],
  credentials: true
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.static('public'));

// PostgreSQL 연결 설정
const pool = new Pool({
  connectionString: process.env.DATABASE_URL || 'postgresql://username:password@localhost:5432/osung_club_db',
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT 미들웨어
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: '접근 권한이 없습니다' });
  }

  jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key', (err, user) => {
    if (err) return res.status(403).json({ error: '유효하지 않은 토큰입니다' });
    req.user = user;
    next();
  });
};

// 관리자 권한 확인
const requireAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: '관리자 권한이 필요합니다' });
  }
  next();
};

// ============= API 라우트 =============

// 헬스체크 엔드포인트
app.get('/api/health', async (req, res) => {
  try {
    // 데이터베이스 연결 확인
    await pool.query('SELECT 1');
    res.json({ 
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: '오성중학교 동아리 시스템',
      version: '1.0.0',
      database: 'connected'
    });
  } catch (error) {
    res.status(503).json({ 
      status: 'unhealthy',
      timestamp: new Date().toISOString(),
      error: 'Database connection failed'
    });
  }
});

// 시스템 정보 엔드포인트
app.get('/api/info', (req, res) => {
  res.json({
    name: '오성중학교 동아리 편성 시스템',
    version: '1.0.0',
    description: '2025학년도 창체동아리 신청 및 편성 관리 시스템',
    features: [
      '동아리 신청 및 편성',
      '실시간 현황 확인',
      '자동 배정 시스템',
      '데이터 내보내기',
      '관리자 대시보드'
    ],
    tech_stack: {
      frontend: 'React 18 + Tailwind CSS',
      backend: 'Node.js + Express.js',
      database: 'PostgreSQL',
      deployment: 'Render.com'
    }
  });
});

// 사용자 인증
app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    
    const userQuery = 'SELECT * FROM users WHERE username = $1';
    const userResult = await pool.query(userQuery, [username]);
    
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: '사용자를 찾을 수 없습니다' });
    }
    
    const user = userResult.rows[0];
    const validPassword = await bcrypt.compare(password, user.password);
    
    if (!validPassword) {
      return res.status(401).json({ error: '비밀번호가 일치하지 않습니다' });
    }
    
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role,
        student_id: user.student_id 
      },
      process.env.JWT_SECRET || 'your-secret-key',
      { expiresIn: '24h' }
    );
    
    res.json({
      token,
      user: {
        id: user.id,
        username: user.username,
        name: user.name,
        role: user.role,
        student_id: user.student_id
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

// 동아리 목록 조회
app.get('/api/clubs', async (req, res) => {
  try {
    const query = `
      SELECT 
        c.*,
        COALESCE(s.current_members, 0) as current_members,
        COALESCE(s.pending_applications, 0) as pending_applications
      FROM clubs c
      LEFT JOIN (
        SELECT 
          club_id,
          COUNT(CASE WHEN status = 'assigned' THEN 1 END) as current_members,
          COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_applications
        FROM applications
        GROUP BY club_id
      ) s ON c.id = s.club_id
      ORDER BY c.name
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching clubs:', error);
    res.status(500).json({ error: '동아리 목록을 불러오는데 실패했습니다' });
  }
});

// 특정 동아리 상세 정보
app.get('/api/clubs/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const query = 'SELECT * FROM clubs WHERE id = $1';
    const result = await pool.query(query, [id]);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: '동아리를 찾을 수 없습니다' });
    }
    
    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching club details:', error);
    res.status(500).json({ error: '동아리 정보를 불러오는데 실패했습니다' });
  }
});

// 학생 동아리 신청
app.post('/api/apply', authenticateToken, async (req, res) => {
  try {
    const { first_choice, second_choice, third_choice } = req.body;
    const student_id = req.user.student_id;
    
    // 기존 신청 삭제
    await pool.query('DELETE FROM applications WHERE student_id = $1', [student_id]);
    
    // 새로운 신청 추가
    const applications = [
      { club_id: first_choice, preference: 1 },
      { club_id: second_choice, preference: 2 },
      { club_id: third_choice, preference: 3 }
    ].filter(app => app.club_id);
    
    for (const app of applications) {
      await pool.query(
        'INSERT INTO applications (student_id, club_id, preference, status) VALUES ($1, $2, $3, $4)',
        [student_id, app.club_id, app.preference, 'pending']
      );
    }
    
    res.json({ message: '동아리 신청이 완료되었습니다' });
  } catch (error) {
    console.error('Error applying for clubs:', error);
    res.status(500).json({ error: '동아리 신청에 실패했습니다' });
  }
});

// 학생 신청 현황 조회
app.get('/api/my-applications', authenticateToken, async (req, res) => {
  try {
    const student_id = req.user.student_id;
    const query = `
      SELECT a.*, c.name as club_name, c.teacher, c.location
      FROM applications a
      JOIN clubs c ON a.club_id = c.id
      WHERE a.student_id = $1
      ORDER BY a.preference
    `;
    
    const result = await pool.query(query, [student_id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ error: '신청 현황을 불러오는데 실패했습니다' });
  }
});

// 관리자: 모든 신청 현황
app.get('/api/admin/applications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        a.*,
        u.name as student_name,
        u.student_id,
        c.name as club_name,
        c.teacher,
        c.max_members
      FROM applications a
      JOIN users u ON a.student_id = u.student_id
      JOIN clubs c ON a.club_id = c.id
      ORDER BY c.name, a.preference, u.name
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching all applications:', error);
    res.status(500).json({ error: '신청 현황을 불러오는데 실패했습니다' });
  }
});

// 관리자: 동아리 배정 실행
app.post('/api/admin/assign-clubs', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 모든 신청을 pending으로 초기화
    await client.query("UPDATE applications SET status = 'pending'");
    
    // 1지망부터 3지망까지 순차적으로 배정
    for (let preference = 1; preference <= 3; preference++) {
      const applications = await client.query(`
        SELECT a.*, c.max_members,
          (SELECT COUNT(*) FROM applications a2 WHERE a2.club_id = a.club_id AND a2.status = 'assigned') as current_assigned
        FROM applications a
        JOIN clubs c ON a.club_id = c.id
        WHERE a.preference = $1 AND a.status = 'pending'
        ORDER BY RANDOM() -- 동점자 처리를 위한 랜덤 정렬
      `, [preference]);
      
      for (const app of applications.rows) {
        if (app.current_assigned < app.max_members) {
          await client.query(
            "UPDATE applications SET status = 'assigned' WHERE student_id = $1 AND club_id = $2",
            [app.student_id, app.club_id]
          );
          
          // 해당 학생의 다른 지망 신청들을 rejected로 변경
          await client.query(
            "UPDATE applications SET status = 'rejected' WHERE student_id = $1 AND club_id != $2",
            [app.student_id, app.club_id]
          );
        }
      }
    }
    
    await client.query('COMMIT');
    res.json({ message: '동아리 배정이 완료되었습니다' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Error assigning clubs:', error);
    res.status(500).json({ error: '동아리 배정에 실패했습니다' });
  } finally {
    client.release();
  }
});

// 관리자: 배정 결과 조회
app.get('/api/admin/assignments', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        c.name as club_name,
        c.teacher,
        c.location,
        c.max_members,
        COUNT(a.student_id) as assigned_count,
        string_agg(u.name || ' (' || u.student_id || ')', ', ' ORDER BY u.name) as students
      FROM clubs c
      LEFT JOIN applications a ON c.id = a.club_id AND a.status = 'assigned'
      LEFT JOIN users u ON a.student_id = u.student_id
      GROUP BY c.id, c.name, c.teacher, c.location, c.max_members
      ORDER BY c.name
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ error: '배정 결과를 불러오는데 실패했습니다' });
  }
});

// 데이터베이스 초기화 엔드포인트 (개발용)
app.post('/api/admin/init-db', async (req, res) => {
  try {
    const initSql = `
      -- 기존 테이블 삭제
      DROP TABLE IF EXISTS applications CASCADE;
      DROP TABLE IF EXISTS clubs CASCADE;
      DROP TABLE IF EXISTS users CASCADE;
      
      -- 사용자 테이블
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password TEXT NOT NULL,
        name VARCHAR(100) NOT NULL,
        student_id VARCHAR(20) UNIQUE,
        role VARCHAR(20) DEFAULT 'student',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- 동아리 테이블
      CREATE TABLE clubs (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        teacher VARCHAR(50) NOT NULL,
        category VARCHAR(50) NOT NULL,
        location VARCHAR(50) NOT NULL,
        max_members INTEGER DEFAULT 15,
        min_members INTEGER DEFAULT 5,
        description TEXT,
        activities TEXT,
        goals TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- 신청 테이블
      CREATE TABLE applications (
        id SERIAL PRIMARY KEY,
        student_id VARCHAR(20) NOT NULL,
        club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
        preference INTEGER NOT NULL CHECK (preference IN (1, 2, 3)),
        status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'rejected')),
        applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
      
      -- 인덱스 생성
      CREATE INDEX idx_applications_student_id ON applications(student_id);
      CREATE INDEX idx_applications_club_id ON applications(club_id);
      CREATE INDEX idx_applications_status ON applications(status);
    `;
    
    await pool.query(initSql);
    res.json({ message: '데이터베이스가 초기화되었습니다' });
  } catch (error) {
    console.error('Database initialization error:', error);
    res.status(500).json({ error: '데이터베이스 초기화에 실패했습니다' });
  }
});

// 정적 파일 제공 (React 앱)
app.get('*', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 오성중학교 동아리 시스템이 포트 ${PORT}에서 실행중입니다`);
  console.log(`📱 접속 주소: http://localhost:${PORT}`);
});