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

// 학생 회원가입 API
app.post('/api/register', async (req, res) => {
  try {
    const { student_number, name } = req.body;
    
    // 입력 검증
    if (!student_number || !name) {
      return res.status(400).json({ error: '학번과 이름을 입력해주세요' });
    }
    
    // 학번 형식 검증 (4자리 숫자)
    if (!/^\d{4}$/.test(student_number)) {
      return res.status(400).json({ error: '학번은 4자리 숫자로 입력해주세요 (예: 1101)' });
    }
    
    // 이름 검증 (한글 2-4글자)
    if (!/^[가-힣]{2,4}$/.test(name)) {
      return res.status(400).json({ error: '이름은 한글 2-4글자로 입력해주세요' });
    }
    
    // 중복 확인
    const existingUser = await pool.query('SELECT id FROM users WHERE username = $1', [student_number]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: '이미 가입된 학번입니다' });
    }
    
    // 비밀번호는 학번과 동일하게 설정
    const password = await bcrypt.hash(student_number, 10);
    
    // 학번에서 학년/반 자동 추출
    const grade = student_number.charAt(0);
    const classNum = student_number.charAt(1);
    const autoClassInfo = `${grade}학년 ${classNum}반`;
    
    // 사용자 생성
    await pool.query(
      'INSERT INTO users (username, password, name, role, class_info, student_id) VALUES ($1, $2, $3, $4, $5, $6)',
      [student_number, password, name, 'student', autoClassInfo, student_number]
    );
    
    res.json({ 
      success: true,
      message: '가입이 완료되었습니다!',
      loginInfo: {
        username: student_number,
        password: student_number,
        classInfo: autoClassInfo,
        note: '로그인 시 아이디와 비밀번호 모두 학번을 사용하세요'
      }
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: '가입 처리 중 오류가 발생했습니다' });
  }
});

// 학번 중복 확인 API
app.get('/api/check-student/:student_number', async (req, res) => {
  try {
    const { student_number } = req.params;
    const result = await pool.query('SELECT id FROM users WHERE username = $1', [student_number]);
    res.json({ exists: result.rows.length > 0 });
  } catch (error) {
    res.status(500).json({ error: '확인 중 오류가 발생했습니다' });
  }
});

// 사용자 인증 (수정됨 - student_id 필드 문제 해결)
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
        student_id: user.student_id || user.username  // student_id 필드 호환성
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
        student_id: user.student_id || user.username,
        class_info: user.class_info
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: '서버 오류가 발생했습니다' });
  }
});

// 동아리 목록 조회 (수정됨 - 스키마 호환성)
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
    
    // 호환성을 위해 필드명 매핑
    const mappedResults = result.rows.map(club => ({
      ...club,
      max_members: club.max_capacity || club.max_members || 30,
      min_members: club.min_members || 5,
      category: club.category || '일반 활동',
      activities: club.activities || club.description || '다양한 활동',
      goals: club.goals || club.requirements || '학생 역량 개발',
      exhibition_plan: club.meeting_time || '학기말 발표'
    }));
    
    res.json(mappedResults);
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

// 학생 동아리 신청 (수정됨 - user_id 기반으로 변경)
app.post('/api/apply', authenticateToken, async (req, res) => {
  try {
    const { first_choice, second_choice, third_choice } = req.body;
    const user_id = req.user.id;  // student_id 대신 id 사용
    
    // 기존 신청 삭제
    await pool.query('DELETE FROM applications WHERE user_id = $1', [user_id]);
    
    // 새로운 신청 추가
    const applications = [
      { club_id: first_choice, priority: 1 },
      { club_id: second_choice, priority: 2 },
      { club_id: third_choice, priority: 3 }
    ].filter(app => app.club_id);
    
    for (const app of applications) {
      await pool.query(
        'INSERT INTO applications (user_id, club_id, priority, status) VALUES ($1, $2, $3, $4)',
        [user_id, app.club_id, app.priority, 'pending']
      );
    }
    
    res.json({ message: '동아리 신청이 완료되었습니다' });
  } catch (error) {
    console.error('Error applying for clubs:', error);
    res.status(500).json({ error: '동아리 신청에 실패했습니다' });
  }
});

// 학생 신청 현황 조회 (수정됨)
app.get('/api/my-applications', authenticateToken, async (req, res) => {
  try {
    const user_id = req.user.id;
    const query = `
      SELECT a.*, c.name as club_name, c.teacher, c.location, a.priority as preference
      FROM applications a
      JOIN clubs c ON a.club_id = c.id
      WHERE a.user_id = $1
      ORDER BY a.priority
    `;
    
    const result = await pool.query(query, [user_id]);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching applications:', error);
    res.status(500).json({ error: '신청 현황을 불러오는데 실패했습니다' });
  }
});

// 관리자: 모든 신청 현황 (수정됨)
app.get('/api/admin/applications', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        a.*,
        u.name as student_name,
        u.username as student_id,
        u.class_info,
        c.name as club_name,
        c.teacher,
        c.max_capacity as max_members,
        a.priority as preference
      FROM applications a
      JOIN users u ON a.user_id = u.id
      JOIN clubs c ON a.club_id = c.id
      ORDER BY c.name, a.priority, u.name
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching all applications:', error);
    res.status(500).json({ error: '신청 현황을 불러오는데 실패했습니다' });
  }
});

// 관리자: 동아리 배정 실행 (수정됨)
app.post('/api/admin/assign-clubs', authenticateToken, requireAdmin, async (req, res) => {
  const client = await pool.connect();
  
  try {
    await client.query('BEGIN');
    
    // 모든 신청을 pending으로 초기화
    await client.query("UPDATE applications SET status = 'pending'");
    
    // 1지망부터 3지망까지 순차적으로 배정
    for (let priority = 1; priority <= 3; priority++) {
      const applications = await client.query(`
        SELECT a.*, c.max_capacity as max_members,
          (SELECT COUNT(*) FROM applications a2 WHERE a2.club_id = a.club_id AND a2.status = 'assigned') as current_assigned
        FROM applications a
        JOIN clubs c ON a.club_id = c.id
        WHERE a.priority = $1 AND a.status = 'pending'
        ORDER BY RANDOM()
      `, [priority]);
      
      for (const app of applications.rows) {
        if (app.current_assigned < app.max_members) {
          await client.query(
            "UPDATE applications SET status = 'assigned' WHERE user_id = $1 AND club_id = $2",
            [app.user_id, app.club_id]
          );
          
          // 해당 학생의 다른 지망 신청들을 rejected로 변경
          await client.query(
            "UPDATE applications SET status = 'rejected' WHERE user_id = $1 AND club_id != $2",
            [app.user_id, app.club_id]
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

// 관리자: 배정 결과 조회 (수정됨)
app.get('/api/admin/assignments', authenticateToken, requireAdmin, async (req, res) => {
  try {
    const query = `
      SELECT 
        c.name as club_name,
        c.teacher,
        c.location,
        c.max_capacity as max_members,
        COUNT(a.user_id) as assigned_count,
        string_agg(u.name || ' (' || u.username || ')', ', ' ORDER BY u.name) as students
      FROM clubs c
      LEFT JOIN applications a ON c.id = a.club_id AND a.status = 'assigned'
      LEFT JOIN users u ON a.user_id = u.id
      GROUP BY c.id, c.name, c.teacher, c.location, c.max_capacity
      ORDER BY c.name
    `;
    
    const result = await pool.query(query);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ error: '배정 결과를 불러오는데 실패했습니다' });
  }
});

// ========================================
// 데이터베이스 자동 초기화 기능 (수정됨)
// ========================================

// 데이터베이스 초기화 라우트
app.get('/init-database', async (req, res) => {
  try {
    console.log('🚀 데이터베이스 초기화 시작...');
    
    // 1. 테이블 생성 (수정된 스키마)
    const createTablesSQL = `
      -- 기존 테이블 삭제 후 재생성
      DROP TABLE IF EXISTS applications CASCADE;
      DROP TABLE IF EXISTS assignments CASCADE;
      DROP TABLE IF EXISTS clubs CASCADE;
      DROP TABLE IF EXISTS users CASCADE;

      -- 사용자 테이블 생성 (수정됨)
      CREATE TABLE users (
          id SERIAL PRIMARY KEY,
          username VARCHAR(50) UNIQUE NOT NULL,
          password VARCHAR(255) NOT NULL,
          name VARCHAR(100) NOT NULL,
          role VARCHAR(20) DEFAULT 'student',
          class_info VARCHAR(20),
          student_id VARCHAR(20),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 동아리 테이블 생성 (수정됨)
      CREATE TABLE clubs (
          id SERIAL PRIMARY KEY,
          name VARCHAR(100) NOT NULL,
          teacher VARCHAR(100) NOT NULL,
          max_capacity INTEGER DEFAULT 30,
          description TEXT,
          requirements TEXT,
          location VARCHAR(100),
          meeting_time VARCHAR(100),
          category VARCHAR(50) DEFAULT '일반 활동',
          min_members INTEGER DEFAULT 5,
          activities TEXT,
          goals TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

      -- 동아리 신청 테이블 생성 (수정됨)
      CREATE TABLE applications (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          club_id INTEGER REFERENCES clubs(id),
          priority INTEGER CHECK (priority IN (1, 2, 3)),
          status VARCHAR(20) DEFAULT 'pending',
          applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id, priority)
      );

      -- 최종 배정 테이블 생성
      CREATE TABLE assignments (
          id SERIAL PRIMARY KEY,
          user_id INTEGER REFERENCES users(id),
          club_id INTEGER REFERENCES clubs(id),
          assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE(user_id)
      );

      -- 인덱스 생성
      CREATE INDEX idx_applications_user_id ON applications(user_id);
      CREATE INDEX idx_applications_club_id ON applications(club_id);
      CREATE INDEX idx_assignments_user_id ON assignments(user_id);
      CREATE INDEX idx_assignments_club_id ON assignments(club_id);
    `;

    await pool.query(createTablesSQL);
    console.log('✅ 테이블 생성 완료');

    // 2. 관리자 계정만 생성 (테스트 학생 계정 제거)
    const adminPassword = await bcrypt.hash('admin123', 10);

    // 관리자 계정 생성
    await pool.query(
      'INSERT INTO users (username, password, name, role) VALUES ($1, $2, $3, $4)',
      ['admin', adminPassword, '시스템 관리자', 'admin']
    );
    console.log('✅ 관리자 계정 생성 완료');

    // 3. 동아리 데이터 생성 (더 현실적인 데이터)
    const clubs = [
      ['축구부', '김체육', 25, '축구를 통한 체력 증진과 팀워크 향상', '운동을 좋아하는 학생', '운동장', '월/수/금 4교시 후', '체육 활동', 5, '축구 경기, 체력 훈련, 팀워크 활동', '전국 중학교 축구 대회 참가'],
      ['과학탐구부', '이과학', 20, '다양한 과학 실험과 탐구 활동', '과학에 관심이 많은 학생', '과학실', '화/목 4교시 후', '학술 활동', 8, '실험 활동, 과학 프로젝트, 과학 전시회 준비', '과학 경진대회 참가 및 수상'],
      ['컴퓨터부', '박정보', 15, '프로그래밍과 컴퓨터 활용 능력 향상', '컴퓨터에 관심이 있는 학생', '컴퓨터실', '월/수 4교시 후', '학술 활동', 6, '프로그래밍 학습, 웹사이트 제작, 앱 개발', '학교 홈페이지 제작 및 관리'],
      ['미술부', '최미술', 18, '다양한 미술 기법 학습과 작품 활동', '그림 그리기를 좋아하는 학생', '미술실', '화/금 4교시 후', '문화예술 활동', 7, '수채화, 유화, 조소, 디자인', '학교 미술 전시회 개최'],
      ['음악부', '한음악', 22, '악기 연주와 합창 활동', '음악을 사랑하는 학생', '음악실', '월/목 4교시 후', '문화예술 활동', 10, '합창, 기악 연주, 음악 이론 학습', '학교 음악회 및 지역 행사 참여'],
      ['독서부', '정독서', 30, '독서 토론과 독후감 작성 활동', '책 읽기를 좋아하는 학생', '도서관', '수/금 4교시 후', '학술 활동', 8, '독서 토론, 독후감 작성, 작가와의 만남', '교내 독서 경연대회 개최'],
      ['영어회화부', '김영어', 20, '원어민과 함께하는 영어회화 연습', '영어 회화 실력 향상을 원하는 학생', '영어교실', '화/목 4교시 후', '학술 활동', 10, '영어 토론, 영어 연극, 원어민과 대화', '영어 말하기 대회 참가'],
      ['댄스부', '이댄스', 16, '다양한 장르의 댄스 배우기', '춤에 관심이 많은 학생', '체육관', '월/수/금 4교시 후', '문화예술 활동', 8, 'K-POP 댄스, 현대무용, 안무 창작', '학교 축제 공연 및 댄스 경연대회']
    ];

    for (const [name, teacher, maxCapacity, description, requirements, location, meetingTime, category, minMembers, activities, goals] of clubs) {
      await pool.query(
        'INSERT INTO clubs (name, teacher, max_capacity, description, requirements, location, meeting_time, category, min_members, activities, goals) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)',
        [name, teacher, maxCapacity, description, requirements, location, meetingTime, category, minMembers, activities, goals]
      );
    }
    console.log('✅ 동아리 데이터 생성 완료');

    // 4. 완료 상태 확인
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

    console.log('📊 데이터베이스 통계:', stats.rows);

    // 5. 성공 응답 (테스트 계정 정보 제거)
    res.json({
      success: true,
      message: '🎉 오성중학교 동아리 시스템 데이터베이스 초기화가 완료되었습니다!',
      statistics: stats.rows,
      clubsCreated: clubs.length,
      nextStep: '학생은 학번과 이름으로 가입 후 동아리를 신청하세요!'
    });

  } catch (error) {
    console.error('❌ 데이터베이스 초기화 오류:', error);
    res.status(500).json({
      success: false,
      message: '데이터베이스 초기화 중 오류가 발생했습니다.',
      error: error.message,
      hint: 'Render 로그를 확인하세요'
    });
  }
});

// 데이터베이스 상태 확인 라우트
app.get('/check-database', async (req, res) => {
  try {
    const tableCheck = await pool.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
      ORDER BY table_name
    `);
    
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

    res.json({
      success: true,
      message: '데이터베이스 상태 정상',
      tables: tableCheck.rows.map(row => row.table_name),
      statistics: stats.rows
    });
  } catch (error) {
    res.json({
      success: false,
      error: error.message,
      message: '데이터베이스 테이블이 아직 생성되지 않았습니다. /init-database를 먼저 실행하세요.'
    });
  }
});

// ========================================
// 정적 파일 제공 (React 앱) - 중요: 이 라우트는 반드시 맨 마지막에 위치해야 함!
// ========================================
app.get('*', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 오성중학교 동아리 시스템이 포트 ${PORT}에서 실행중입니다`);
  console.log(`📱 접속 주소: http://localhost:${PORT}`);
});
