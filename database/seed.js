const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
require('dotenv').config();

// PostgreSQL 연결 설정
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// 2025학년도 창체동아리 부서 데이터
const clubsData = [
  {
    name: '애니메이션반',
    teacher: '정유진',
    category: '문화예술 활동',
    location: '미술실',
    max_members: 12,
    min_members: 5,
    exhibition_plan: '전시',
    description: '디지털 애니메이션과 웹툰 제작을 통해 창의성과 예술적 감성을 기르는 동아리입니다.',
    activities: '애니메이션 기초 이론 학습, 캐릭터 디자인, 스토리보드 제작, 디지털 애니메이션 제작, 웹툰 그리기',
    goals: '디지털 아트 역량 강화 및 창의적 표현력 개발'
  },
  {
    name: '또래상담반',
    teacher: '김아람',
    category: '그 밖의 필요한 활동',
    location: '위클래스',
    max_members: 10,
    min_members: 5,
    exhibition_plan: '전시',
    description: '또래 친구들의 고민을 들어주고 함께 해결책을 찾아가는 상담 봉사 동아리입니다.',
    activities: '상담 기법 학습, 의사소통 훈련, 공감능력 개발, 또래상담 실습, 학교폭력 예방 캠페인',
    goals: '공감능력과 의사소통능력 향상, 건전한 학교문화 조성'
  },
  {
    name: '필사적글쓰기반(형설관)',
    teacher: '김재철',
    category: '문화예술 활동',
    location: '형설관',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '글쓰기를 통해 창의적 사고력과 표현력을 기르는 문학 창작 동아리입니다.',
    activities: '창작 기법 학습, 시/소설/수필 쓰기, 문학 작품 감상, 작품 발표회, 교내 문집 제작',
    goals: '문학적 감수성과 창의적 표현력 개발'
  },
  {
    name: '수화반',
    teacher: '김희정',
    category: '문화예술 활동',
    location: '2-1',
    max_members: 12,
    min_members: 5,
    exhibition_plan: '전시',
    description: '수화를 배우고 소통의 다양성을 이해하는 봉사정신 함양 동아리입니다.',
    activities: '수화 기초 학습, 수화 노래 연습, 청각장애인 문화 이해, 수화 공연 준비, 봉사활동',
    goals: '소통의 다양성 이해 및 배려심 함양'
  },
  {
    name: '독서영화토론반',
    teacher: '이은재',
    category: '문화예술 활동',
    location: '3-1',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '독서와 영화 감상을 통해 비판적 사고력과 토론 능력을 기르는 동아리입니다.',
    activities: '도서 및 영화 선정, 작품 분석, 토론 진행, 서평 작성, 영화 리뷰 작성, 발표 활동',
    goals: '비판적 사고력과 논리적 표현력 개발'
  },
  {
    name: '보드게임반',
    teacher: '조준상',
    category: '문화예술 활동',
    location: '3-2',
    max_members: 12,
    min_members: 5,
    exhibition_plan: '전시',
    description: '다양한 보드게임을 통해 전략적 사고와 협동심을 기르는 동아리입니다.',
    activities: '보드게임 룰 학습, 전략 게임 체험, 협동 게임 진행, 게임 대회 개최, 새로운 게임 개발',
    goals: '전략적 사고력과 협동심 개발'
  },
  {
    name: '비타민반',
    teacher: '명정화',
    category: '그 밖의 필요한 활동',
    location: '보건실',
    max_members: 10,
    min_members: 5,
    exhibition_plan: '수요일 6교시 창의적 체험활동 실시',
    description: '건강한 생활습관 형성과 보건 지식을 배우는 건강 증진 동아리입니다.',
    activities: '건강 교육, 응급처치 실습, 건강 캠페인 활동, 보건 상식 퀴즈, 건강한 식습관 교육',
    goals: '올바른 건강 의식 함양 및 건강한 생활습관 형성'
  },
  {
    name: '배드민턴반',
    teacher: '백도훈',
    category: '스포츠 활동',
    location: '체육관',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '배드민턴을 통해 체력 증진과 스포츠맨십을 기르는 운동 동아리입니다.',
    activities: '배드민턴 기초 기술 연습, 실전 경기, 체력 훈련, 배드민턴 대회 참가, 규칙 학습',
    goals: '체력 증진 및 스포츠맨십 함양'
  },
  {
    name: '생활스포츠반',
    teacher: '정대희',
    category: '스포츠 활동',
    location: '운동장 및 동합지원실',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '발표',
    description: '다양한 생활 스포츠를 체험하며 건강한 신체와 정신을 기르는 동아리입니다.',
    activities: '축구, 농구, 피구, 줄넘기, 탁구 등 다양한 스포츠 체험, 경기 규칙 학습, 스포츠 대회 기획',
    goals: '다양한 스포츠 경험을 통한 체력 증진'
  },
  {
    name: '국악반',
    teacher: '김수원',
    category: '문화예술 활동',
    location: '공달실',
    max_members: 12,
    min_members: 5,
    exhibition_plan: '전시',
    description: '우리나라 전통 음악을 배우고 전통문화의 아름다움을 느끼는 동아리입니다.',
    activities: '전통 악기 연주법 학습, 국악 이론 공부, 전통 민요 배우기, 국악 공연 준비, 전통문화 체험',
    goals: '전통문화에 대한 이해와 자긍심 함양'
  },
  {
    name: '모바일보드게임반',
    teacher: '신민섭',
    category: '문화예술 활동',
    location: '가사실',
    max_members: 12,
    min_members: 5,
    exhibition_plan: '전시',
    description: '모바일과 보드게임을 융합한 새로운 형태의 게임을 체험하는 동아리입니다.',
    activities: '디지털 보드게임 체험, 게임 개발 이론, 창의적 게임 제작, 게임 대회 개최, 게임 리뷰 작성',
    goals: '창의적 사고력과 디지털 리터러시 개발'
  },
  {
    name: '창작댄스반',
    teacher: '이은지',
    category: '문화예술 활동',
    location: '컴퓨터실',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '다양한 장르의 댄스를 배우고 창작하여 예술적 표현력을 기르는 동아리입니다.',
    activities: 'K-POP 댄스, 현대무용, 창작 안무, 댄스 배틀, 공연 준비, 음악과 동작의 조화 연구',
    goals: '신체 표현력과 예술적 감성 개발'
  },
  {
    name: '날아보자(VR드론초종)반',
    teacher: '전용권',
    category: '그 밖의 필요한 활동',
    location: '진로상담실',
    max_members: 10,
    min_members: 5,
    exhibition_plan: '전시',
    description: 'VR과 드론 기술을 체험하며 4차 산업혁명 시대의 기술을 이해하는 동아리입니다.',
    activities: 'VR 콘텐츠 체험, 드론 조종 실습, 코딩 교육, 미래 기술 탐구, 진로 탐색 활동',
    goals: '미래 기술에 대한 이해와 진로 탐색 능력 개발'
  },
  {
    name: '영어회화반',
    teacher: '김선영',
    category: '학술 활동',
    location: '어학실',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '실용적인 영어 회화 능력을 기르고 다양한 문화를 이해하는 동아리입니다.',
    activities: '일상 영어 회화 연습, 영어 게임, 영어 노래 부르기, 외국 문화 탐구, 영어 연극 공연',
    goals: '실용적 영어 능력과 국제적 소양 개발'
  },
  {
    name: '필사적글쓰기반(도서관)',
    teacher: '이은화',
    category: '문화예술 활동',
    location: '도서관',
    max_members: 15,
    min_members: 5,
    exhibition_plan: '전시',
    description: '독서와 글쓰기를 통해 사고력과 표현력을 기르는 문학 동아리입니다.',
    activities: '독서 활동, 창작 글쓰기, 독서토론, 작가와의 만남, 교내 문학 잡지 제작',
    goals: '독서 습관 형성과 창의적 표현력 개발'
  }
];

// 샘플 학생 데이터
const studentsData = [
  { username: '20251001', name: '김민수', student_id: '20251001', grade: 1, class_num: 1 },
  { username: '20251002', name: '이지은', student_id: '20251002', grade: 1, class_num: 1 },
  { username: '20251003', name: '박준호', student_id: '20251003', grade: 1, class_num: 2 },
  { username: '20251004', name: '최서연', student_id: '20251004', grade: 2, class_num: 1 },
  { username: '20251005', name: '정하은', student_id: '20251005', grade: 2, class_num: 2 },
  { username: '20251006', name: '김태현', student_id: '20251006', grade: 3, class_num: 1 },
  { username: '20251007', name: '송유진', student_id: '20251007', grade: 3, class_num: 2 },
  { username: '20251008', name: '장민석', student_id: '20251008', grade: 1, class_num: 3 },
  { username: '20251009', name: '윤소영', student_id: '20251009', grade: 2, class_num: 3 },
  { username: '20251010', name: '한지훈', student_id: '20251010', grade: 3, class_num: 3 },
  { username: '20251011', name: '오예린', student_id: '20251011', grade: 1, class_num: 1 },
  { username: '20251012', name: '구자현', student_id: '20251012', grade: 1, class_num: 2 },
  { username: '20251013', name: '배수지', student_id: '20251013', grade: 2, class_num: 1 },
  { username: '20251014', name: '임도윤', student_id: '20251014', grade: 2, class_num: 2 },
  { username: '20251015', name: '황시우', student_id: '20251015', grade: 3, class_num: 1 }
];

// 교사 데이터
const teachersData = [
  { username: 'teacher001', name: '정유진', role: 'teacher' },
  { username: 'teacher002', name: '김아람', role: 'teacher' },
  { username: 'teacher003', name: '김재철', role: 'teacher' },
  { username: 'teacher004', name: '김희정', role: 'teacher' },
  { username: 'teacher005', name: '이은재', role: 'teacher' }
];

async function seedDatabase() {
  const client = await pool.connect();
  
  try {
    console.log('🚀 데이터베이스 시드 작업을 시작합니다...');
    
    await client.query('BEGIN');
    
    // 기존 데이터 정리
    console.log('📝 기존 데이터 정리 중...');
    await client.query('DELETE FROM applications');
    await client.query('DELETE FROM clubs WHERE id > 0');
    await client.query('DELETE FROM users WHERE role != \'admin\'');
    await client.query('ALTER SEQUENCE clubs_id_seq RESTART WITH 1');
    await client.query('ALTER SEQUENCE users_id_seq RESTART WITH 2'); // admin 계정 이후부터
    
    // 동아리 데이터 입력
    console.log('🏫 동아리 데이터 입력 중...');
    for (const club of clubsData) {
      await client.query(`
        INSERT INTO clubs (name, teacher, category, location, max_members, min_members, exhibition_plan, description, activities, goals)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `, [
        club.name, club.teacher, club.category, club.location, 
        club.max_members, club.min_members, club.exhibition_plan,
        club.description, club.activities, club.goals
      ]);
    }
    
    // 비밀번호 해싱 (모든 테스트 계정은 'student123')
    const hashedPassword = await bcrypt.hash('student123', 10);
    
    // 학생 계정 생성
    console.log('👨‍🎓 학생 계정 생성 중...');
    for (const student of studentsData) {
      await client.query(`
        INSERT INTO users (username, password, name, student_id, grade, class_num, role)
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        student.username, hashedPassword, student.name, 
        student.student_id, student.grade, student.class_num, 'student'
      ]);
    }
    
    // 교사 계정 생성
    console.log('👨‍🏫 교사 계정 생성 중...');
    for (const teacher of teachersData) {
      await client.query(`
        INSERT INTO users (username, password, name, role)
        VALUES ($1, $2, $3, $4)
      `, [teacher.username, hashedPassword, teacher.name, teacher.role]);
    }
    
    // 샘플 신청 데이터 생성 (테스트용)
    console.log('📄 샘플 신청 데이터 생성 중...');
    const sampleApplications = [
      { student_id: '20251001', club_id: 1, preference: 1 }, // 김민수 -> 애니메이션반
      { student_id: '20251001', club_id: 3, preference: 2 }, // 김민수 -> 필사적글쓰기반
      { student_id: '20251001', club_id: 8, preference: 3 }, // 김민수 -> 배드민턴반
      
      { student_id: '20251002', club_id: 12, preference: 1 }, // 이지은 -> 창작댄스반
      { student_id: '20251002', club_id: 1, preference: 2 },  // 이지은 -> 애니메이션반
      { student_id: '20251002', club_id: 14, preference: 3 }, // 이지은 -> 영어회화반
      
      { student_id: '20251003', club_id: 8, preference: 1 },  // 박준호 -> 배드민턴반
      { student_id: '20251003', club_id: 9, preference: 2 },  // 박준호 -> 생활스포츠반
      { student_id: '20251003', club_id: 6, preference: 3 },  // 박준호 -> 보드게임반
    ];
    
    for (const app of sampleApplications) {
      await client.query(`
        INSERT INTO applications (student_id, club_id, preference, status)
        VALUES ($1, $2, $3, 'pending')
      `, [app.student_id, app.club_id, app.preference]);
    }
    
    await client.query('COMMIT');
    
    // 결과 확인
    const clubCount = await client.query('SELECT COUNT(*) FROM clubs');
    const studentCount = await client.query('SELECT COUNT(*) FROM users WHERE role = \'student\'');
    const applicationCount = await client.query('SELECT COUNT(*) FROM applications');
    
    console.log('✅ 데이터베이스 시드 작업이 완료되었습니다!');
    console.log(`📊 동아리 수: ${clubCount.rows[0].count}개`);
    console.log(`👨‍🎓 학생 수: ${studentCount.rows[0].count}명`);
    console.log(`📝 신청 수: ${applicationCount.rows[0].count}건`);
    console.log('');
    console.log('🔑 테스트 계정 정보:');
    console.log('   관리자: admin / admin123');
    console.log('   학생: 20251001 / student123');
    console.log('   교사: teacher001 / student123');
    
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('❌ 데이터베이스 시드 작업 중 오류 발생:', error);
    throw error;
  } finally {
    client.release();
  }
}

// 스크립트 실행
if (require.main === module) {
  seedDatabase()
    .then(() => {
      console.log('🎉 시드 작업이 성공적으로 완료되었습니다!');
      process.exit(0);
    })
    .catch((error) => {
      console.error('💥 시드 작업 실패:', error);
      process.exit(1);
    });
}

module.exports = { seedDatabase };