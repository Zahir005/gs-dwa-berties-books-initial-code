-- Insert data into the tables

USE berties_books;

-- Seed books table
INSERT INTO books (name, price)
VALUES
  ('Brighton Rock', 20.25),
  ('Brave New World', 25.00),
  ('Animal Farm', 12.99);

-- Seed default login user for marking:
-- username: gold
-- password: smiths
INSERT INTO users (username, first_name, last_name, email, password_hash)
VALUES
  ('gold', 'Gold', 'User', 'gold@example.com', '$2b$10$dvmafyM293LjS1.Dh88Am.V0UZCRXcTfqh1i7vs0Xv/jakVYzt//a');
