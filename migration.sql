-- ============================================================
-- LETUS 백엔드 전환 마이그레이션
-- Supabase SQL Editor에서 실행하세요
-- ============================================================

-- 1. profiles 테이블에 pw_hash 컬럼 추가 (bcrypt 해시 저장용)
ALTER TABLE profiles ADD COLUMN IF NOT EXISTS pw_hash TEXT;
ALTER TABLE pending  ADD COLUMN IF NOT EXISTS pw_hash TEXT;

-- 2. 기존 관리자 비밀번호 초기화 안내
--    (기존 Supabase Auth 비밀번호는 백엔드에서 사용 불가)
--    → 아래 UPDATE로 임시 비밀번호 해시를 넣거나,
--      백엔드 실행 후 /api/auth/password 엔드포인트로 변경하세요.
--
-- 임시 비밀번호 "Admin1234!" 의 bcrypt 해시 (rounds=12):
-- $2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9G
-- (실제 배포 전 반드시 변경하세요!)

-- UPDATE profiles
-- SET pw_hash = '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdBPj4J/HS.iK9G'
-- WHERE email = 'admin@example.com';

-- 3. 확인
SELECT id, name, email, role,
       CASE WHEN pw_hash IS NOT NULL THEN '✅ 설정됨' ELSE '❌ 미설정' END AS pw_status
FROM profiles;
