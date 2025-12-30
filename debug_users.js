import db from './db.js';

const users = db.prepare('SELECT * FROM users').all();
const roles = db.prepare('SELECT * FROM user_roles').all();

console.log('Roles:', roles);
console.log('Users:', users);
