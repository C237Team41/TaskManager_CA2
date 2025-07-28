const express = require('express');
const mysql = require('mysql2');
const session = require('express-session');
const flash = require('connect-flash');
const bcrypt = require('bcryptjs');
const app = express();

// MySQL database connection
const connection = mysql.createConnection({
    host: 'a58spk.h.filess.io',
    port: 3307,
    user: 'TASKMANAGER2_principal',
    password: '00699cf33828b9c274c08cf23dcca991756d5b14',
    database: 'TASKMANAGER2_principal'
});

connection.connect(err => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
        return;
    }
    console.log('Connected to MySQL database');
});

// Middleware
app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

app.use(session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    cookie: { 
        maxAge: 1000 * 60 * 60 * 24 * 7,
        secure: false,
        httpOnly: true
    }
}));

app.use(flash());

// Authentication middlewares
const checkAuthenticated = (req, res, next) => {
    if (req.session.user) return next();
    req.flash('error', 'Please log in to view this resource');
    res.redirect('/login');
};

const checkAdmin = (req, res, next) => {
    if (req.session.user?.role === 'admin') return next();
    req.flash('error', 'Access denied');
    res.redirect('/tasks');
};

// Home route
app.get('/', (req, res) => {
    res.render('index', { user: req.session.user });
});

// Register routes
app.get('/register', (req, res) => {
    res.render('register', { 
        messages: req.flash('error'),
        formData: req.flash('formData')[0] || {}
    });
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        req.flash('error', 'All fields are required');
        req.flash('formData', req.body);
        return res.redirect('/register');
    }

    if (password.length < 6) {
        req.flash('error', 'Password must be at least 6 characters');
        req.flash('formData', req.body);
        return res.redirect('/register');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const sql = 'INSERT INTO users (username, email, password, role, active) VALUES (?, ?, ?, "user", true)';
        connection.query(sql, [username, email, hashedPassword], err => {
            if (err) {
                req.flash('error', 'Username or email already exists');
                req.flash('formData', req.body);
                return res.redirect('/register');
            }
            req.flash('success', 'Registration successful! Please login');
            res.redirect('/login');
        });
    } catch (err) {
        console.error(err);
        req.flash('error', 'Registration failed');
        req.flash('formData', req.body);
        res.redirect('/register');
    }
});

// Login routes
app.get('/login', (req, res) => {
    res.render('login', { 
        success: req.flash('success'),
        error: req.flash('error'),
        formData: req.flash('formData')[0] || {}
    });
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        req.flash('error', 'All fields are required');
        req.flash('formData', { email });
        return res.redirect('/login');
    }

    const sql = 'SELECT * FROM users WHERE email = ?';
    connection.query(sql, [email], async (err, results) => {
        if (err || results.length === 0) {
            req.flash('error', 'Invalid credentials');
            req.flash('formData', { email });
            return res.redirect('/login');
        }

        const user = results[0];

        if (!user.active) {
            req.flash('error', 'Your account is deactivated. Contact admin.');
            req.flash('formData', { email });
            return res.redirect('/login');
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            req.flash('error', 'Invalid credentials');
            req.flash('formData', { email });
            return res.redirect('/login');
        }

        req.session.user = user;
        req.flash('success', 'Login successful!');
        res.redirect('/tasks');
    });
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) console.error('Session destruction error:', err);
        res.redirect('/');
    });
});

// Task routes
app.get('/tasks', checkAuthenticated, (req, res) => {
    const { search, status } = req.query;
    const isAdmin = req.session.user.role === 'admin';
    let sql = '';
    let params = [];

    if (isAdmin) {
        sql = 'SELECT t.*, u.username FROM tasks t JOIN users u ON t.user_id = u.id WHERE 1=1';
        if (search) {
            sql += ' AND t.title LIKE ?';
            params.push(`%${search}%`);
        }
        if (status && status !== 'all') {
            sql += ' AND t.status = ?';
            params.push(status);
        }
    } else {
        sql = 'SELECT * FROM tasks WHERE user_id = ?';
        params.push(req.session.user.id);
    }

    connection.query(sql, params, (err, tasks) => {
        if (err) {
            console.error(err);
            req.flash('error', 'Failed to load tasks');
            return res.redirect('/');
        }
        res.render('tasks', {
            tasks: tasks || [],
            user: req.session.user,
            success: req.flash('success'),
            error: req.flash('error'),
            search: search || '',
            status: status || 'all'
        });
    });
});

app.post('/tasks', checkAuthenticated, (req, res) => {
    const { title, description, category } = req.body;

    if (!title) {
        req.flash('error', 'Title is required');
        return res.redirect('/tasks');
    }

    const sql = 'INSERT INTO tasks (title, description, category, user_id) VALUES (?, ?, ?, ?)';
    connection.query(sql, [title, description || null, category || null, req.session.user.id], err => {
        if (err) {
            console.error(err);
            req.flash('error', 'Failed to add task');
            return res.redirect('/tasks');
        }
        req.flash('success', 'Task added successfully');
        res.redirect('/tasks');
    });
});

// Update task route
app.post('/tasks/:id/update', checkAuthenticated, (req, res) => {
    const taskId = req.params.id;
    const { title, description, category, status } = req.body;

    if (!title) {
        req.flash('error', 'Title is required');
        return res.redirect('/tasks');
    }

    // Only allow admins or owner to update
    if (req.session.user.role !== 'admin') {
        const checkOwnerSql = 'SELECT user_id FROM tasks WHERE id = ?';
        connection.query(checkOwnerSql, [taskId], (err, results) => {
            if (err || results.length === 0 || results[0].user_id !== req.session.user.id) {
                req.flash('error', 'Unauthorized to edit this task');
                return res.redirect('/tasks');
            }
            updateTask();
        });
    } else {
        updateTask();
    }

    function updateTask() {
        const updateSql = 'UPDATE tasks SET title = ?, description = ?, category = ?, status = ? WHERE id = ?';
        connection.query(updateSql, [title, description || null, category || null, status || 'pending', taskId], err => {
            if (err) {
                console.error(err);
                req.flash('error', 'Failed to update task');
            } else {
                req.flash('success', 'Task updated successfully');
            }
            res.redirect('/tasks');
        });
    }
});

// Delete task route
app.post('/tasks/:id/delete', checkAuthenticated, (req, res) => {
    const taskId = req.params.id;

    // Only admins or owner can delete task
    if (req.session.user.role !== 'admin') {
        const checkOwnerSql = 'SELECT user_id FROM tasks WHERE id = ?';
        connection.query(checkOwnerSql, [taskId], (err, results) => {
            if (err || results.length === 0 || results[0].user_id !== req.session.user.id) {
                req.flash('error', 'Unauthorized to delete this task');
                return res.redirect('/tasks');
            }
            deleteTask();
        });
    } else {
        deleteTask();
    }

    function deleteTask() {
        const deleteSql = 'DELETE FROM tasks WHERE id = ?';
        connection.query(deleteSql, [taskId], err => {
            if (err) {
                console.error(err);
                req.flash('error', 'Failed to delete task');
            } else {
                req.flash('success', 'Task deleted successfully');
            }
            res.redirect('/tasks');
        });
    }
});

// Admin User Management Routes
app.get('/users', checkAuthenticated, checkAdmin, (req, res) => {
    const sql = 'SELECT id, username, email, role, active FROM users';
    connection.query(sql, (err, users) => {
        if (err) {
            req.flash('error', 'Failed to load users');
            return res.redirect('/tasks');
        }
        res.render('users', {
            users,
            user: req.session.user,
            success: req.flash('success'),
            error: req.flash('error')
        });
    });
});

app.post('/users/:id/toggle-role', checkAuthenticated, checkAdmin, (req, res) => {
    const userId = req.params.id;
    const currentRole = req.body.currentRole;
    const newRole = currentRole === 'admin' ? 'user' : 'admin';

    if (userId == req.session.user.id && newRole !== 'admin') {
        req.flash('error', 'You cannot change your own admin role.');
        return res.redirect('/users');
    }

    connection.query('UPDATE users SET role = ? WHERE id = ?', [newRole, userId], err => {
        if (err) req.flash('error', 'Failed to change role');
        else req.flash('success', `Role updated to ${newRole}`);
        res.redirect('/users');
    });
});

app.post('/users/:id/toggle-active', checkAuthenticated, checkAdmin, (req, res) => {
    const userId = req.params.id;
    const currentStatus = req.body.currentStatus === 'true';
    const newStatus = !currentStatus;

    if (userId == req.session.user.id && !newStatus) {
        req.flash('error', 'You cannot deactivate your own account.');
        return res.redirect('/users');
    }

    connection.query('UPDATE users SET active = ? WHERE id = ?', [newStatus, userId], err => {
        if (err) req.flash('error', 'Failed to update user status');
        else req.flash('success', `User has been ${newStatus ? 'activated' : 'deactivated'}`);
        res.redirect('/users');
    });
});

app.post('/users/:id/delete', checkAuthenticated, checkAdmin, (req, res) => {
    const userId = req.params.id;

    if (userId == req.session.user.id) {
        req.flash('error', 'Cannot delete your own account');
        return res.redirect('/users');
    }

    connection.query('DELETE FROM users WHERE id = ?', [userId], err => {
        if (err) {
            console.error(err);
            req.flash('error', 'Failed to delete user');
        } else {
            req.flash('success', 'User deleted successfully');
        }
        res.redirect('/users');
    });
});

// Error handler
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send(`
        <html>
        <head>
            <title>Error</title>
            <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        </head>
        <body class="bg-light">
            <div class="container mt-5">
                <div class="alert alert-danger">
                    <h2>Something went wrong!</h2>
                    <p>${err.message}</p>
                    <a href="/" class="btn btn-primary">Go Home</a>
                </div>
            </div>
        </body>
        </html>
    `);
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

