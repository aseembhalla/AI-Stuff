-- Create database
CREATE DATABASE api_key_manager;

-- Switch to the database
\c api_key_manager

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(120) UNIQUE NOT NULL,
    google_id VARCHAR(100) UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create api_keys table
CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    key_name VARCHAR(100) NOT NULL,
    api_key VARCHAR(32) UNIQUE NOT NULL,
    creation_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expiry_date TIMESTAMP WITH TIME ZONE NOT NULL,
    status VARCHAR(20) DEFAULT 'active',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes
CREATE INDEX idx_user_id ON api_keys(user_id);
CREATE INDEX idx_api_key ON api_keys(api_key);
CREATE INDEX idx_key_name ON api_keys(key_name);

-- Create trigger function to update updated_at timestamp
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create trigger to update updated_at on api_keys table
CREATE TRIGGER update_api_keys_updated_at
    BEFORE UPDATE ON api_keys
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Sample data (uncomment to use)
-- INSERT INTO users (email, google_id) VALUES 
--     ('user1@example.com', 'google123'),
--     ('user2@example.com', 'google456');

-- INSERT INTO api_keys (user_id, key_name, api_key, expiry_date) VALUES
--     (1, 'test-key-1', 'api_key_1234567890abcdef1234567890abcdef', NOW() + INTERVAL '30 days'),
--     (2, 'test-key-2', 'api_key_abcdef1234567890abcdef1234567890', NOW() + INTERVAL '30 days');
