CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  username VARCHAR(80) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role VARCHAR(20) NOT NULL CHECK (role IN ('admin','staff','student')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS students (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  student_id VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(150) NOT NULL,
  class_name VARCHAR(30) NOT NULL,
  section VARCHAR(20),
  parent_name VARCHAR(150),
  phone VARCHAR(30),
  annual_fee NUMERIC(12,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS staff (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT UNIQUE REFERENCES users(id) ON DELETE SET NULL,
  staff_id VARCHAR(50) UNIQUE NOT NULL,
  name VARCHAR(150) NOT NULL,
  role_title VARCHAR(100),
  phone VARCHAR(30),
  monthly_salary NUMERIC(12,2) NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE TABLE IF NOT EXISTS fee_payments (
  id BIGSERIAL PRIMARY KEY,
  student_id BIGINT NOT NULL REFERENCES students(id) ON DELETE CASCADE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  payment_date DATE NOT NULL DEFAULT CURRENT_DATE,
  receipt_no VARCHAR(60) UNIQUE NOT NULL,
  note TEXT
);
CREATE TABLE IF NOT EXISTS salary_payments (
  id BIGSERIAL PRIMARY KEY,
  staff_id BIGINT NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  payment_date DATE NOT NULL DEFAULT CURRENT_DATE,
  note TEXT
);
CREATE TABLE IF NOT EXISTS expenses (
  id BIGSERIAL PRIMARY KEY,
  title VARCHAR(180) NOT NULL,
  amount NUMERIC(12,2) NOT NULL CHECK (amount > 0),
  expense_date DATE NOT NULL DEFAULT CURRENT_DATE,
  note TEXT
);
CREATE INDEX IF NOT EXISTS fee_student_idx ON fee_payments(student_id);
CREATE INDEX IF NOT EXISTS fee_date_idx ON fee_payments(payment_date);
CREATE INDEX IF NOT EXISTS salary_date_idx ON salary_payments(payment_date);
CREATE INDEX IF NOT EXISTS expense_date_idx ON expenses(expense_date);
