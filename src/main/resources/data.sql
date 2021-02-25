INSERT INTO app_user (username, password, enabled, account_non_expired, account_non_locked, credentials_non_expired) VALUES
('sharath', 'pass', true, true, true, true),
('vivek', 'pass', true, true, true, true),
('gopal', 'pass', false, true, true, true),
('deb', 'pass', true, false, true, true),
('soorya', 'pass', true, true, false, true),
('ravi', 'pass', true, true, true, false),
('rohit', 'pass', false, false, false, false);

INSERT INTO role (authority) VALUES
('ROLE_ADMIN'),
('ROLE_USER');

INSERT INTO user_role (user_id, role_id) VALUES
(1, 1),
(1, 2),
(2, 2),
(3, 2),
(4, 2),
(5, 2),
(6, 2),
(7, 2);