-- database/optimization.sql
-- 데이터베이스 성능 최적화를 위한 인덱스 및 제약조건

-- 1. 인덱스 생성 (성능 향상)
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_student_id ON users(student_id);

CREATE INDEX IF NOT EXISTS idx_applications_user_id ON applications(user_id);
CREATE INDEX IF NOT EXISTS idx_applications_club_id ON applications(club_id);
CREATE INDEX IF NOT EXISTS idx_applications_status ON applications(status);
CREATE INDEX IF NOT EXISTS idx_applications_priority ON applications(priority);

CREATE INDEX IF NOT EXISTS idx_clubs_category ON clubs(category);
CREATE INDEX IF NOT EXISTS idx_clubs_name ON clubs(name);

-- 2. 복합 인덱스 (자주 함께 조회되는 컬럼들)
CREATE INDEX IF NOT EXISTS idx_applications_user_priority ON applications(user_id, priority);
CREATE INDEX IF NOT EXISTS idx_applications_club_status ON applications(club_id, status);

-- 3. 부분 인덱스 (조건부 인덱스로 공간 절약)
CREATE INDEX IF NOT EXISTS idx_applications_pending ON applications(club_id) 
    WHERE status = 'pending';
CREATE INDEX IF NOT EXISTS idx_applications_assigned ON applications(user_id) 
    WHERE status = 'assigned';

-- 4. 성능 모니터링용 뷰 생성
CREATE OR REPLACE VIEW v_club_statistics AS
SELECT 
    c.id,
    c.name,
    c.teacher,
    c.category,
    c.max_capacity,
    COUNT(a.id) as total_applications,
    COUNT(CASE WHEN a.status = 'pending' THEN 1 END) as pending_count,
    COUNT(CASE WHEN a.status = 'assigned' THEN 1 END) as assigned_count,
    COUNT(CASE WHEN a.status = 'rejected' THEN 1 END) as rejected_count,
    ROUND(
        (COUNT(CASE WHEN a.status = 'assigned' THEN 1 END)::float / 
         NULLIF(c.max_capacity, 0)) * 100, 
        2
    ) as capacity_percentage
FROM clubs c
LEFT JOIN applications a ON c.id = a.club_id
GROUP BY c.id, c.name, c.teacher, c.category, c.max_capacity
ORDER BY c.name;

-- 5. 사용자 통계 뷰
CREATE OR REPLACE VIEW v_user_statistics AS
SELECT 
    role,
    COUNT(*) as user_count,
    COUNT(CASE WHEN last_login IS NOT NULL THEN 1 END) as active_users,
    COUNT(CASE WHEN last_login > NOW() - INTERVAL '7 days' THEN 1 END) as recent_active
FROM users
GROUP BY role;

-- 6. 신청 현황 요약 뷰
CREATE OR REPLACE VIEW v_application_summary AS
SELECT 
    status,
    priority,
    COUNT(*) as count,
    COUNT(DISTINCT user_id) as unique_users,
    COUNT(DISTINCT club_id) as unique_clubs
FROM applications
GROUP BY status, priority
ORDER BY priority, status;

-- 7. 데이터 정합성 체크 함수
CREATE OR REPLACE FUNCTION check_data_integrity()
RETURNS TABLE(
    check_name TEXT,
    status TEXT,
    details TEXT
) AS $$
BEGIN
    -- 중복 신청 체크
    RETURN QUERY
    SELECT 
        'duplicate_applications'::TEXT,
        CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END::TEXT,
        'Found ' || COUNT(*) || ' duplicate applications'::TEXT
    FROM (
        SELECT user_id, club_id, COUNT(*)
        FROM applications 
        GROUP BY user_id, club_id 
        HAVING COUNT(*) > 1
    ) dups;
    
    -- 우선순위 중복 체크
    RETURN QUERY
    SELECT 
        'duplicate_priorities'::TEXT,
        CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END::TEXT,
        'Found ' || COUNT(*) || ' users with duplicate priorities'::TEXT
    FROM (
        SELECT user_id, priority, COUNT(*)
        FROM applications 
        GROUP BY user_id, priority 
        HAVING COUNT(*) > 1
    ) dup_priorities;
    
    -- 과할당 체크 (동아리 정원 초과)
    RETURN QUERY
    SELECT 
        'over_capacity'::TEXT,
        CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END::TEXT,
        'Found ' || COUNT(*) || ' clubs over capacity'::TEXT
    FROM (
        SELECT c.id, c.max_capacity, COUNT(a.id) as assigned
        FROM clubs c
        LEFT JOIN applications a ON c.id = a.club_id AND a.status = 'assigned'
        GROUP BY c.id, c.max_capacity
        HAVING COUNT(a.id) > c.max_capacity
    ) over_cap;
    
    -- 다중 배정 체크 (한 학생이 여러 동아리에 배정)
    RETURN QUERY
    SELECT 
        'multiple_assignments'::TEXT,
        CASE WHEN COUNT(*) > 0 THEN 'FAIL' ELSE 'PASS' END::TEXT,
        'Found ' || COUNT(*) || ' users with multiple assignments'::TEXT
    FROM (
        SELECT user_id, COUNT(*)
        FROM applications 
        WHERE status = 'assigned'
        GROUP BY user_id 
        HAVING COUNT(*) > 1
    ) multi_assigned;
END;
$$ LANGUAGE plpgsql;

-- 8. 정기 청소 함수 (오래된 토큰, 로그 등)
CREATE OR REPLACE FUNCTION cleanup_old_data()
RETURNS TEXT AS $$
DECLARE
    cleaned_count INTEGER := 0;
BEGIN
    -- 30일 이상 로그인하지 않은 임시 계정 정리 (필요시)
    -- DELETE FROM users WHERE role = 'temp' AND last_login < NOW() - INTERVAL '30 days';
    -- GET DIAGNOSTICS cleaned_count = ROW_COUNT;
    
    RETURN 'Cleanup completed. Processed ' || cleaned_count || ' records.';
END;
$$ LANGUAGE plpgsql;

-- 9. 백업용 덤프 함수
CREATE OR REPLACE FUNCTION export_application_data()
RETURNS TABLE(
    student_id TEXT,
    student_name TEXT,
    class_info TEXT,
    club_name TEXT,
    teacher TEXT,
    priority INTEGER,
    status TEXT,
    applied_at TIMESTAMP
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        u.student_id::TEXT,
        u.name::TEXT,
        u.class_info::TEXT,
        c.name::TEXT,
        c.teacher::TEXT,
        a.priority,
        a.status::TEXT,
        a.applied_at
    FROM applications a
    JOIN users u ON a.user_id = u.id
    JOIN clubs c ON a.club_id = c.id
    ORDER BY u.class_info, u.name, a.priority;
END;
$$ LANGUAGE plpgsql;

-- 10. 성능 모니터링용 통계
CREATE OR REPLACE VIEW v_system_performance AS
SELECT 
    'total_users' as metric,
    COUNT(*)::TEXT as value
FROM users
UNION ALL
SELECT 
    'total_clubs' as metric,
    COUNT(*)::TEXT as value
FROM clubs
UNION ALL
SELECT 
    'total_applications' as metric,
    COUNT(*)::TEXT as value
FROM applications
UNION ALL
SELECT 
    'pending_applications' as metric,
    COUNT(*)::TEXT as value
FROM applications WHERE status = 'pending'
UNION ALL
SELECT 
    'assigned_applications' as metric,
    COUNT(*)::TEXT as value
FROM applications WHERE status = 'assigned'
UNION ALL
SELECT 
    'database_size' as metric,
    pg_size_pretty(pg_database_size(current_database()))::TEXT as value;
