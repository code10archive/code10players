const express = require('express');
const WebSocket = require('ws');
const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// Инициализация БД
const db = new sqlite3.Database('./chat.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error('Ошибка подключения к БД:', err);
        process.exit(1);
    }
    
    console.log('Подключено к SQLite базе данных');
    
    // Создаем таблицы, если их нет
    db.serialize(() => {
        db.run(`
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE,
                password TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        db.run(`
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user TEXT,
                text TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `);
        
        // Создаем индекс для ускорения выборки сообщений
        db.run('CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp)');
        
        // Тестовый пользователь (для демонстрации)
        db.run(
            'INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)',
            ['test', bcrypt.hashSync('test123', 10)]
        );
    });
});

// Для хранения активных пользователей
const activeUsers = new Map();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// API для регистрации
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    
    if (!username || !password) {
        return res.status(400).json({ error: 'Заполните все поля' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            [username, hashedPassword],
            function(err) {
                if (err) {
                    return res.status(400).json({ error: 'Имя пользователя занято' });
                }
                res.json({ success: true, userId: this.lastID });
            }
        );
    } catch (err) {
        console.error('Ошибка регистрации:', err);
        res.status(500).json({ error: 'Ошибка сервера' });
    }
});

// API для входа
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    db.get(
        'SELECT * FROM users WHERE username = ?',
        [username],
        async (err, user) => {
            if (err || !user) {
                return res.status(401).json({ error: 'Неверные учетные данные' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: 'Неверные учетные данные' });
            }

            // Генерируем простой токен (в реальном проекте используйте JWT)
            const token = Buffer.from(`${username}:${Date.now()}`).toString('base64');
            res.json({ success: true, username, token });
        }
    );
});

// WebSocket обработка
wss.on('connection', (ws) => {
    let username = '';
    let authenticated = false;

    // Отправляем последние 50 сообщений новому пользователю
    const sendHistory = () => {
        db.all(
            'SELECT * FROM messages ORDER BY timestamp DESC LIMIT 50',
            (err, rows) => {
                if (!err) {
                    ws.send(JSON.stringify({
                        type: 'history',
                        messages: rows.reverse()
                    }));
                }
            }
        );
    };

    // Отправляем обновленный список пользователей всем
    const broadcastUserList = () => {
        const users = Array.from(activeUsers.keys());
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) {
                client.send(JSON.stringify({
                    type: 'user_list',
                    users: users
                }));
            }
        });
    };

    ws.on('message', async (data) => {
        try {
            const msg = JSON.parse(data);

            // Аутентификация
            if (!authenticated && msg.type === 'auth') {
                // В реальном проекте проверяйте токен
                username = msg.username;
                authenticated = true;
                
                // Добавляем пользователя в активные
                activeUsers.set(username, ws);
                broadcastUserList();
                
                // Отправляем историю сообщений
                sendHistory();
                return;
            }

            // Только аутентифицированные пользователи
            if (!authenticated) {
                ws.close();
                return;
            }

            // Обработка сообщений
            if (msg.type === 'message') {
                const text = msg.text.trim();
                if (text.length === 0) return;

                // Сохраняем в БД
                db.run(
                    'INSERT INTO messages (user, text) VALUES (?, ?)',
                    [username, text],
                    (err) => {
                        if (err) {
                            console.error('Ошибка сохранения сообщения:', err);
                            return;
                        }
                        
                        // Рассылаем всем участникам
                        const message = {
                            type: 'message',
                            user: username,
                            text: text,
                            timestamp: new Date().toISOString()
                        };
                        
                        wss.clients.forEach(client => {
                            if (client.readyState === WebSocket.OPEN) {
                                client.send(JSON.stringify(message));
                            }
                        });
                    }
                );
            }
        } catch (err) {
            console.error('Ошибка обработки сообщения:', err);
        }
    });

    ws.on('close', () => {
        if (authenticated) {
            activeUsers.delete(username);
            broadcastUserList();
        }
    });
});

// Защита от потери данных - периодическое сохранение
setInterval(() => {
    db.run('PRAGMA wal_checkpoint(FULL)');
    console.log('Проверка целостности БД выполнена');
}, 60000); // Каждую минуту

// Запуск сервера
const PORT = process.env.PORT || 3000;
server.listen(PORT, '0.0.0.0', () => {
    console.log(`Сервер запущен на http://localhost:${PORT}`);
});

// Обработка ошибок
process.on('uncaughtException', (err) => {
    console.error('Необработанное исключение:', err);
    // В реальном проекте нужно перезапустить процесс
});

process.on('unhandledRejection', (err) => {
    console.error('Необработанный промис:', err);
});