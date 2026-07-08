-- assets_topology.db 初始化脚本
-- 用于创建 SQLite 数据库表结构和测试数据

CREATE TABLE IF NOT EXISTS nodes (
    id TEXT PRIMARY KEY,
    domain TEXT,
    ip TEXT,
    loc TEXT,
    lat REAL,
    lng REAL,
    type TEXT,
    tags TEXT,
    details TEXT
);

CREATE TABLE IF NOT EXISTS edges (
    source TEXT,
    target TEXT,
    type TEXT
);

-- 插入测试数据 (可选)
INSERT OR IGNORE INTO nodes (id, domain, ip, loc, lat, lng, type, tags) VALUES 
('1', 'example.com', '104.21.34.22', 'San Francisco, US', 37.7749, -122.4194, 'normal', '电商平台,B2B 业务'),
('2', 'shop-example.com', '192.168.1.1', 'New York, US', 40.7128, -74.0060, 'normal', '电商平台'),
('3', 'global-trade.net', '8.8.8.8', 'London, UK', 51.5074, -0.1278, 'normal', '贸易门户'),
('4', 'b2b-portal.org', '1.1.1.1', 'Tokyo, JP', 35.6895, 139.6917, 'normal', 'B2B 业务'),
('5', 'cdn-node-1.net', '172.64.10.1', 'Singapore', 1.3521, 103.8198, 'cdn', 'CDN分发'),
('6', 'scam-site-A.com', '45.12.33.1', 'Moscow, RU', 55.7558, 37.6173, 'scam', '高危站群'),
('7', 'scam-site-B.com', '45.12.33.2', 'St Petersburg, RU', 59.9343, 30.3351, 'scam', '高危站群'),
('8', 'analytics-tracker.com', '8.8.4.4', 'Paris, FR', 48.8566, 2.3522, 'normal', '数据分析'),
('9', 'malicious-redirect.org', '103.22.11.0', 'Sydney, AU', -33.8688, 151.2093, 'scam', '恶意重定向');

INSERT OR IGNORE INTO edges (source, target, type) VALUES 
('6', '7', 'ssl'),
('6', '9', 'ssl'),
('1', '3', 'ip'),
('1', '5', 'cdn'),
('2', '5', 'cdn'),
('8', '5', 'cdn'),
('4', '1', 'link'),
('8', '1', 'link'),
('8', '2', 'link');
