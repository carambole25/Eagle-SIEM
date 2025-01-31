USE eagle_db;
CREATE TABLE IF NOT EXISTS events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    hostname VARCHAR(100),
    log TEXT
);
CREATE TABLE IF NOT EXISTS api_keys (
    id INT AUTO_INCREMENT PRIMARY KEY,
    api_key VARCHAR(100)
);
CREATE TABLE IF NOT EXISTS save_query (
    id INT AUTO_INCREMENT PRIMARY KEY,
    query TEXT
);