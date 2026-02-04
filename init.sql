-- Users (The people logging in)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash TEXT NOT NULL, -- Use bcrypt
  created_at TIMESTAMP DEFAULT NOW()
);

-- OAuth Sessions (Managed by node-oidc-provider)
CREATE TABLE IF NOT EXISTS oauth_payloads (
  id VARCHAR(255) PRIMARY KEY,
  type VARCHAR(255) NOT NULL,
  payload JSONB NOT NULL,
  grant_id VARCHAR(255),
  expires_at TIMESTAMP
);

-- Notes (The actual application data - MemoryBank)
CREATE TABLE IF NOT EXISTS notes (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID REFERENCES users(id),
  content TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT NOW()
);
