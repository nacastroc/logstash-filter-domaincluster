-- = Logstash's DomainCluster filter plugin database creation script
--
-- This script creates an SQLite3 database to be used
-- with Logstash's DomainCluster filter plugin. It creates the necesary
-- tables for the plugin to work while adding some test data.
--
-- Run by typing the following shell command:
-- [source,bash]
-- sqlite3 -init domaincluster.db.create.sql testdb.sqlite
--

-- Enable enforcing of foreign keys
PRAGMA foreign_keys = ON;

-- Create tables
CREATE TABLE `Cluster` (
	`_id`	INTEGER PRIMARY KEY,
	`name`	TEXT NOT NULL UNIQUE
);

CREATE TABLE `Pattern` (
	`_id`	INTEGER PRIMARY KEY,
	`pattern`	TEXT NOT NULL UNIQUE,
    `cluster_id`    INTEGER NOT NULL,
    FOREIGN KEY(`cluster_id`) REFERENCES `Cluster`(`_id`)
);

-- Insert Cluster test data
INSERT INTO `Cluster` VALUES (1,"Social Network");
INSERT INTO `Cluster` VALUES (2,"Business Network");
INSERT INTO `Cluster` VALUES (3,"Research Network");
INSERT INTO `Cluster` VALUES (4,"EMail Service");

-- Insert Pattern test data
INSERT INTO `Pattern` VALUES (1,'\.facebook\.com',1);
INSERT INTO `Pattern` VALUES (2,'\.twitter\.com',1);
INSERT INTO `Pattern` VALUES (3,'\.myspace\.com',1);
INSERT INTO `Pattern` VALUES (4,'\.linkedin\.com',2);
INSERT INTO `Pattern` VALUES (5,'\.angel\.co$',2);
INSERT INTO `Pattern` VALUES (6,'\.networkingforprofessionals\.com',2);
INSERT INTO `Pattern` VALUES (7,'\.researchgate\.net',3);
INSERT INTO `Pattern` VALUES (8,'scholar\.google\.com',3);
INSERT INTO `Pattern` VALUES (9,'mail\.com',4);

-- A sample select statement to get a logical view of, at most, 10 elements
SELECT p.pattern, c.name FROM Pattern p JOIN Cluster c on c._id = p.cluster_id LIMIT 10;
