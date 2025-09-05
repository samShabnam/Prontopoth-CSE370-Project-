-- Create database (run this if you haven't created the DB yet)
-- CREATE DATABASE protnopoth_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Use the database
-- USE protnopoth_db;

DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  nid VARCHAR(50) NOT NULL,
  email VARCHAR(255) NOT NULL UNIQUE,
  phone VARCHAR(20),
  password_hash VARCHAR(20) NOT NULL,
  role ENUM('Archaeologist','Admin','Museum Manager','Caretaker','General User') DEFAULT 'General User',
  profile_pic VARCHAR(255),
  is_verified TINYINT(1) DEFAULT 0,
  otp_code VARCHAR(6),
  otp_expires DATETIME,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
