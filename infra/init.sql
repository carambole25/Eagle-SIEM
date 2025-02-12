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
CREATE TABLE IF NOT EXISTS ui_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username TEXT,
    pass TEXT
);
INSERT INTO ui_users (username, pass) 
VALUES ('admin', '$2y$10$jQIbh/FMEPJFJw1NyiIVHupksDNhSPCotRKtk.LElUfmKYXMG0QO6')