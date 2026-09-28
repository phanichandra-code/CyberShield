CREATE DATABASE IF NOT EXISTS cybershield;

USE cybershield;


CREATE TABLE IF NOT EXISTS alerts (

    alert_id INT AUTO_INCREMENT PRIMARY KEY,

    alert_type VARCHAR(100) NOT NULL,

    ip_address VARCHAR(45) NOT NULL,

    details TEXT,

    severity VARCHAR(20) NOT NULL DEFAULT 'Medium',

    detected_at DATETIME NOT NULL

);

USE cybershield;

SELECT * FROM alerts;