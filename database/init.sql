-- 오성중학교 동아리 시스템 데이터베이스 스키마

-- 기존 테이블 삭제 (순서 중요)
DROP TABLE IF EXISTS applications CASCADE;
DROP TABLE IF EXISTS clubs CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- 사용자 테이블 (학생 및 관리자)
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password TEXT NOT NULL,
    name VARCHAR(100) NOT NULL,
    student_id VARCHAR(20) UNIQUE, -- 학생의 경우 학번, 관리자는 NULL
    grade INTEGER, -- 학년 (1, 2, 3)
    class_num INTEGER, -- 반 번호
    role VARCHAR(20) DEFAULT 'student' CHECK (role IN ('student', 'admin', 'teacher')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 동아리 테이블
CREATE TABLE clubs (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    teacher VARCHAR(50) NOT NULL,
    category VARCHAR(50) NOT NULL,
    location VARCHAR(50) NOT NULL,
    max_members INTEGER DEFAULT 15 CHECK (max_members <= 15 AND max_members >= 5),
    min_members INTEGER DEFAULT 5,
    description TEXT DEFAULT '동아리 활동을 통해 창의성과 협동심을 기릅니다.',
    activities TEXT DEFAULT '다양한 체험활동과 프로젝트를 진행합니다.',
    goals TEXT DEFAULT '학생들의 전인적 성장을 돕습니다.',
    exhibition_plan VARCHAR(10) DEFAULT '전시' CHECK (exhibition_plan IN ('전시', '발표', '수요일 6교시 창의적 체험활동 실시')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 동아리 신청 테이블
CREATE TABLE applications (
    id SERIAL PRIMARY KEY,
    student_id VARCHAR(20) NOT NULL,
    club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
    preference INTEGER NOT NULL CHECK (preference IN (1, 2, 3)),
    status VARCHAR(20) DEFAULT 'pending' CHECK (status IN ('pending', 'assigned', 'rejected')),
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_at TIMESTAMP,
    notes TEXT, -- 배정 시 특이사항
    UNIQUE(student_id, club_id), -- 동일 학생이 같은 동아리에 중복 신청 방지
    UNIQUE(student_id, preference) -- 동일 학생이 같은 순위로 중복 신청 방지
);

-- 동아리 활동 기록 테이블 (확장성을 위해)
CREATE TABLE club_activities (
    id SERIAL PRIMARY KEY,
    club_id INTEGER REFERENCES clubs(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    activity_date DATE,
    created_by INTEGER REFERENCES users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 인덱스 생성 (성능 최적화)
CREATE INDEX idx_users_student_id ON users(student_id);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_applications_student_id ON applications(student_id);
CREATE INDEX idx_applications_club_id ON applications(club_id);
CREATE INDEX idx_applications_status ON applications(status);
CREATE INDEX idx_applications_preference ON applications(preference);
CREATE INDEX idx_clubs_category ON clubs(category);
CREATE INDEX idx_club_activities_club_id ON club_activities(club_id);
CREATE INDEX idx_club_activities_date ON club_activities(activity_date);

-- 트리거 함수: updated_at 자동 업데이트
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- 트리거 생성
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_clubs_updated_at BEFORE UPDATE ON clubs FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- 기본 관리자 계정 생성 (비밀번호: admin123)
INSERT INTO users (username, password, name, role) VALUES 
('admin', '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', '시스템 관리자', 'admin');

-- 기본 설정 확인 쿼리
-- SELECT 'Database initialized successfully' as status;