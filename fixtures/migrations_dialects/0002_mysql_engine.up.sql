-- dialect: mysql (synthetic fixture)
CREATE TABLE IF NOT EXISTS demo_dialect_my (
    id INT AUTO_INCREMENT PRIMARY KEY,
    label VARCHAR(20) NOT NULL
) ENGINE=InnoDB;
INSERT INTO demo_dialect_my (id, label) VALUES (1, 'demo')
ON DUPLICATE KEY UPDATE label = VALUES(label);
