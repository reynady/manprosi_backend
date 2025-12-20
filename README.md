# Palm Oil Monitoring - Backend API

Backend API untuk sistem monitoring kelapa sawit.

## Prerequisites

- Node.js (v18 atau lebih baru)
- MySQL/MariaDB (via XAMPP)
- Database `palm_oil_monitoring` sudah dibuat

## Setup

### 1. Install Dependencies

```bash
npm install
```

### 2. Konfigurasi Database

Edit file `.env` dan sesuaikan dengan konfigurasi database Anda:

```env
PORT=8000
DB_HOST=127.0.0.1
DB_USER=root
DB_PASSWORD=          # Kosongkan jika tidak ada password
DB_NAME=palm_oil_monitoring
SESSION_SECRET=your-secret-key-change-this-in-production
```

### 3. Setup Database

Import schema database dari folder `../manprosi-frontend-main/database/`:

```bash
# Masuk ke folder frontend
cd ../manprosi-frontend-main

# Import schema
mysql -u root -p < database/mysql_schema.sql
mysql -u root -p < database/mysql_seed.sql
```

### 4. Jalankan Server

```bash
# Development mode (auto-reload)
npm run dev

# Production mode
npm start
```

Server akan berjalan di `http://127.0.0.1:8000`

## API Endpoints

### Authentication
- `POST /login` - Login user
- `GET /me` - Get current user
- `POST /logout` - Logout

### Users (Admin only)
- `GET /users` - Get all users
- `POST /users` - Create user
- `DELETE /users/:id` - Delete user

### Lands
- `GET /users/:userId/lands` - Get user's lands
- `POST /lands` - Create land
- `DELETE /lands/:id` - Delete land

### Sensors
- `GET /lands/:landId/sensors` - Get land's sensors

### Plants
- `GET /lands/:landId/plants` - Get land's plants

## Default Users

Setelah import seed data, gunakan:
- **Admin:** username=`admin`, password=`password123`
- **Farmer:** username=`farmer1`, password=`password123`
- **Consultant:** username=`consultant1`, password=`password123`

## Troubleshooting

### Database connection failed
- Pastikan MySQL/MariaDB sudah berjalan (via XAMPP)
- Cek konfigurasi di file `.env`
- Pastikan database `palm_oil_monitoring` sudah dibuat

### Port already in use
- Ubah `PORT` di file `.env`
- Atau stop aplikasi lain yang menggunakan port 8000

### CORS error
- Pastikan frontend berjalan di `http://localhost:3000`
- Cek konfigurasi CORS di `server.js`


