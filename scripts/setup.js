#!/usr/bin/env node

/**
 * 오성중학교 동아리 시스템 자동 설정 스크립트
 * 
 * 이 스크립트는 다음 작업을 수행합니다:
 * 1. 환경 변수 파일 생성
 * 2. 데이터베이스 연결 확인
 * 3. 스키마 초기화
 * 4. 시드 데이터 입력
 * 5. 개발 서버 실행
 */

const fs = require('fs');
const path = require('path');
const { execSync, spawn } = require('child_process');
const readline = require('readline');

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

// 색상 코드
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m'
};

function colorLog(color, message) {
  console.log(colors[color] + message + colors.reset);
}

function question(prompt) {
  return new Promise((resolve) => {
    rl.question(prompt, resolve);
  });
}

function checkCommand(command) {
  try {
    execSync(`${command} --version`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

async function checkPrerequisites() {
  colorLog('cyan', '\n🔍 시스템 요구사항 확인 중...\n');
  
  const requirements = [
    { name: 'Node.js', command: 'node', required: true },
    { name: 'npm', command: 'npm', required: true },
    { name: 'PostgreSQL', command: 'psql', required: true },
    { name: 'Git', command: 'git', required: false }
  ];
  
  let allGood = true;
  
  for (const req of requirements) {
    const available = checkCommand(req.command);
    const status = available ? '✅' : '❌';
    const requiredText = req.required ? '(필수)' : '(선택)';
    
    console.log(`${status} ${req.name} ${requiredText}`);
    
    if (!available && req.required) {
      allGood = false;
      colorLog('red', `   → ${req.name}이 설치되지 않았습니다. 설치 후 다시 실행해주세요.`);
    }
  }
  
  if (!allGood) {
    colorLog('red', '\n❌ 필수 프로그램이 설치되지 않았습니다.');
    colorLog('yellow', '\n설치 가이드:');
    colorLog('white', '• Node.js: https://nodejs.org/');
    colorLog('white', '• PostgreSQL: https://www.postgresql.org/download/');
    process.exit(1);
  }
  
  colorLog('green', '\n✅ 모든 요구사항이 충족되었습니다!\n');
}

async function createEnvFile() {
  colorLog('cyan', '🔧 환경 변수 설정 중...\n');
  
  const envPath = path.join(__dirname, '..', '.env');
  
  if (fs.existsSync(envPath)) {
    const overwrite = await question('❓ .env 파일이 이미 존재합니다. 덮어쓰시겠습니까? (y/N): ');
    if (overwrite.toLowerCase() !== 'y') {
      colorLog('yellow', '⏭️  .env 파일 생성을 건너뜁니다.');
      return;
    }
  }
  
  colorLog('white', '데이터베이스 연결 정보를 입력해주세요:');
  
  const dbHost = await question('📍 호스트 (localhost): ') || 'localhost';
  const dbPort = await question('🔌 포트 (5432): ') || '5432';
  const dbName = await question('🗄️  데이터베이스 이름 (osung_club_db): ') || 'osung_club_db';
  const dbUser = await question('👤 사용자명 (postgres): ') || 'postgres';
  const dbPassword = await question('🔑 비밀번호: ');
  
  const databaseUrl = `postgresql://${dbUser}:${dbPassword}@${dbHost}:${dbPort}/${dbName}`;
  
  const envContent = `# 오성중학교 동아리 시스템 환경 변수
# 자동 생성됨 - ${new Date().toLocaleString()}

# 서버 설정
PORT=3000
NODE_ENV=development

# 데이터베이스 연결
DATABASE_URL=${databaseUrl}

# 보안 설정
JWT_SECRET=osung-middle-school-club-system-${Date.now()}-${Math.random().toString(36)}
BCRYPT_SALT_ROUNDS=10

# CORS 설정
CORS_ORIGIN=http://localhost:3000

# 기타 설정
MAX_FILE_SIZE=10
LOG_LEVEL=info
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
`;
  
  fs.writeFileSync(envPath, envContent);
  colorLog('green', '✅ .env 파일이 생성되었습니다!');
}

async function testDatabaseConnection() {
  colorLog('cyan', '\n🔗 데이터베이스 연결 테스트 중...\n');
  
  try {
    // .env 파일 로드
    require('dotenv').config({ path: path.join(__dirname, '..', '.env') });
    
    const { Pool } = require('pg');
    const pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: false
    });
    
    await pool.query('SELECT NOW()');
    await pool.end();
    
    colorLog('green', '✅ 데이터베이스 연결 성공!');
    return true;
  } catch (error) {
    colorLog('red', '❌ 데이터베이스 연결 실패:');
    colorLog('red', `   ${error.message}`);
    return false;
  }
}

async function initializeDatabase() {
  colorLog('cyan', '\n🗄️  데이터베이스 초기화 중...\n');
  
  try {
    // 스키마 초기화
    colorLog('white', '📋 스키마 생성 중...');
    execSync('npm run db:init', { stdio: 'inherit' });
    
    // 시드 데이터 입력
    colorLog('white', '🌱 시드 데이터 입력 중...');
    execSync('npm run db:seed', { stdio: 'inherit' });
    
    colorLog('green', '✅ 데이터베이스 초기화 완료!');
    return true;
  } catch (error) {
    colorLog('red', '❌ 데이터베이스 초기화 실패:');
    colorLog('red', `   ${error.message}`);
    return false;
  }
}

async function installDependencies() {
  colorLog('cyan', '\n📦 패키지 설치 중...\n');
  
  try {
    execSync('npm install', { stdio: 'inherit' });
    colorLog('green', '✅ 패키지 설치 완료!');
  } catch (error) {
    colorLog('red', '❌ 패키지 설치 실패:');
    colorLog('red', `   ${error.message}`);
    process.exit(1);
  }
}

function startDevServer() {
  colorLog('cyan', '\n🚀 개발 서버 시작 중...\n');
  
  colorLog('green', '✅ 설정이 완료되었습니다!');
  colorLog('white', '\n📋 접속 정보:');
  colorLog('white', '   🌐 웹사이트: http://localhost:3000');
  colorLog('white', '   👤 관리자: admin / admin123');
  colorLog('white', '   👨‍🎓 학생: 20251001 / student123');
  
  colorLog('yellow', '\n⚡ 개발 서버를 시작합니다...');
  colorLog('magenta', '   (종료하려면 Ctrl+C를 누르세요)\n');
  
  const server = spawn('npm', ['run', 'dev'], { 
    stdio: 'inherit',
    shell: true 
  });
  
  process.on('SIGINT', () => {
    colorLog('yellow', '\n🛑 서버를 종료합니다...');
    server.kill();
    process.exit(0);
  });
}

async function main() {
  console.clear();
  
  colorLog('magenta', '🏫 오성중학교 동아리 편성 시스템');
  colorLog('white', '   자동 설정 스크립트 v1.0.0\n');
  colorLog('cyan', '=' .repeat(50));
  
  try {
    // 1. 시스템 요구사항 확인
    await checkPrerequisites();
    
    // 2. 패키지 설치
    await installDependencies();
    
    // 3. 환경 변수 설정
    await createEnvFile();
    
    // 4. 데이터베이스 연결 테스트
    const dbConnected = await testDatabaseConnection();
    if (!dbConnected) {
      colorLog('yellow', '\n⚠️  데이터베이스 연결에 실패했지만 계속 진행합니다.');
      colorLog('white', '   나중에 수동으로 연결 정보를 확인해주세요.');
    }
    
    // 5. 데이터베이스 초기화
    if (dbConnected) {
      const dbInitialized = await initializeDatabase();
      if (!dbInitialized) {
        colorLog('yellow', '\n⚠️  데이터베이스 초기화에 실패했습니다.');
        colorLog('white', '   나중에 수동으로 초기화해주세요: npm run db:reset');
      }
    }
    
    // 6. 개발 서버 시작 여부 확인
    const startServer = await question('\n🚀 개발 서버를 시작하시겠습니까? (Y/n): ');
    if (startServer.toLowerCase() !== 'n') {
      rl.close();
      startDevServer();
    } else {
      colorLog('green', '\n✅ 설정이 완료되었습니다!');
      colorLog('white', '\n수동 실행 명령어:');
      colorLog('white', '   npm run dev  # 개발 서버 시작');
      colorLog('white', '   npm start    # 운영 서버 시작');
      rl.close();
    }
    
  } catch (error) {
    colorLog('red', '\n💥 설정 중 오류가 발생했습니다:');
    colorLog('red', `   ${error.message}`);
    rl.close();
    process.exit(1);
  }
}

// 스크립트 실행
if (require.main === module) {
  main();
}

module.exports = { main };