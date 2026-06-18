const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');

// JWT 密钥（生产环境必须通过环境变量注入）
const JWT_SECRET = process.env.JWT_SECRET || 'todo-list-dev-secret-change-in-production';
const JWT_EXPIRES = '7d';

// ==================== 安全中间件 ====================

// 隐藏技术栈信息
app.disable('x-powered-by');

// HTTP 安全头（helmet）
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            imgSrc: ["'self'", "data:"],
            connectSrc: ["'self'"],
        },
    },
}));

// CORS：只允许自己的域名
const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS
    ? process.env.ALLOWED_ORIGINS.split(',')
    : ['https://todo-list-7edt.onrender.com', 'http://localhost:3000', 'http://localhost:5500', 'http://127.0.0.1:5500'];
app.use(cors({
    origin: function (origin, callback) {
        // 允许无 origin 的请求（如 curl、Postman、同源）
        if (!origin || ALLOWED_ORIGINS.includes(origin)) {
            callback(null, true);
        } else {
            callback(null, false);
        }
    },
    credentials: true,
}));

app.use(express.json({ limit: '10kb' }));

// 全局速率限制：每 IP 每 15 分钟 100 次
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: '请求过于频繁，请稍后再试' },
});
app.use('/api/', globalLimiter);

// 登录/注册更严格：每 IP 每 15 分钟 10 次
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: '尝试次数过多，请 15 分钟后再试' },
});

// ==================== JWT 认证中间件 ====================
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ error: '未授权，请先登录' });
    }
    try {
        const token = authHeader.split(' ')[1];
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // { username, iat, exp }
        next();
    } catch (e) {
        return res.status(401).json({ error: '登录已过期，请重新登录' });
    }
}

// 可选认证：如果带了 Token 就解析，但不强制
function optionalAuth(req, res, next) {
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
        try {
            const token = authHeader.split(' ')[1];
            req.user = jwt.verify(token, JWT_SECRET);
        } catch (e) { /* token 无效，忽略 */ }
    }
    next();
}

// ==================== 输入验证 ====================
const USERNAME_REGEX = /^[一-龥a-zA-Z0-9_]{2,20}$/;

function validateUsername(username) {
    if (!username || typeof username !== 'string') return '用户名不能为空';
    if (!USERNAME_REGEX.test(username)) return '用户名只能包含中文、字母、数字和下划线，长度2-20';
    return null;
}

function validatePassword(password) {
    if (!password || typeof password !== 'string') return '密码不能为空';
    if (password.length < 8) return '密码至少8位';
    if (!/[A-Z]/.test(password)) return '密码需包含大写字母';
    if (!/[a-z]/.test(password)) return '密码需包含小写字母';
    if (!/[0-9]/.test(password)) return '密码需包含数字';
    return null;
}

// ==================== 数据读写 ====================
function readData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            writeData({ users: [], tasks: [], groups: [], dailyGoals: [], dailySummaries: [], checkIns: [] });
        }
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const data = JSON.parse(raw);
        if (!data.groups) data.groups = [];
        if (!data.dailyGoals) data.dailyGoals = [];
        if (!data.dailySummaries) data.dailySummaries = [];
        if (!data.checkIns) data.checkIns = [];
        data.tasks = data.tasks.map(t => ({
            title: '', description: '', tags: [], status: 'todo',
            priorityScore: 0, sortOrder: Date.now(), deadline: null,
            timeBlock: null, owner: '', groupId: null, supervisor: null,
            visibility: 'public', isDaily: false, dailyDate: null,
            createdAt: new Date().toISOString(), completedAt: null,
            ...t
        }));
        data.users = data.users.map(u => ({
            stats: { streak: 0, longestStreak: 0, totalCompleted: 0, lastCompletedDate: null, weeklyCompletions: 0 },
            ...u
        }));
        return data;
    } catch (e) {
        return { users: [], tasks: [], groups: [], dailyGoals: [], dailySummaries: [], checkIns: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

function todayStr() {
    return new Date().toISOString().slice(0, 10);
}

function genId() {
    return Date.now().toString(36) + Math.random().toString(36).slice(2, 7);
}

// ==================== 权限辅助 ====================

// 获取用户可见的其他用户集合（同组成员）
function getVisibleUsers(data, username) {
    const visible = new Set([username]);
    data.groups.forEach(g => {
        const isMember = g.members.find(m => m.username === username);
        if (isMember) {
            g.members.forEach(m => visible.add(m.username));
        }
    });
    return visible;
}

// 检查用户是否有权操作某个任务
function canModifyTask(data, taskId, username) {
    const task = data.tasks.find(t => t.id === taskId);
    if (!task) return false;
    if (task.owner === username) return true;
    // 组长可以管理小组成员的任务
    const group = data.groups.find(g => g.id === task.groupId);
    if (group && group.owner === username) return true;
    return false;
}

// ==================== 优先级计算 ====================
function calcPriority(task) {
    if (task.status === 'done') return -1;
    if (!task.deadline) return task.isDaily ? 35 : 25;
    const now = new Date();
    const dl = new Date(task.deadline);
    const diffDays = (dl - now) / (1000 * 60 * 60 * 24);
    let score = 0;
    if (diffDays < 0) score += Math.min(100, Math.abs(diffDays) * 30);
    else if (diffDays < 1) score += 50;
    else score += Math.min(50, (1 / diffDays) * 50);
    if (task.isDaily) score += 10;
    return Math.round(score);
}

// ==================== 用户统计更新 ====================
function updateUserStats(data, username) {
    const user = data.users.find(u => u.username === username);
    if (!user) return;
    const completed = data.tasks.filter(t => t.owner === username && t.status === 'done');
    user.stats.totalCompleted = completed.length;
    const today = todayStr();
    if (user.stats.lastCompletedDate !== today) {
        const yesterday = new Date();
        yesterday.setDate(yesterday.getDate() - 1);
        const yesterdayStr = yesterday.toISOString().slice(0, 10);
        if (user.stats.lastCompletedDate === yesterdayStr) {
            user.stats.streak = (user.stats.streak || 0) + 1;
        } else {
            user.stats.streak = 1;
        }
        user.stats.lastCompletedDate = today;
        if (user.stats.streak > (user.stats.longestStreak || 0)) {
            user.stats.longestStreak = user.stats.streak;
        }
    }
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - now.getDay());
    weekStart.setHours(0, 0, 0, 0);
    user.stats.weeklyCompletions = completed.filter(t =>
        t.completedAt && new Date(t.completedAt) >= weekStart
    ).length;
}

// ==================== 每日任务自动生成 ====================
function ensureDailyTasks(data, username, date) {
    const templates = data.tasks.filter(t => t.isDaily && t.owner === username && !t.dailyDate);
    const existing = data.tasks.filter(t => t.isDaily && t.owner === username && t.dailyDate === date);
    const existingTitles = new Set(existing.map(t => t.title));

    templates.forEach(tpl => {
        if (!existingTitles.has(tpl.title)) {
            const dailyTask = {
                ...tpl,
                id: genId(),
                dailyDate: date,
                status: 'todo',
                completedAt: null,
                createdAt: new Date().toISOString(),
                sortOrder: Date.now(),
            };
            data.tasks.push(dailyTask);
        }
    });
}

// ==================== API 路由 ====================

// 对认证端点应用更严格的速率限制
app.use('/api/login', authLimiter);
app.use('/api/register', authLimiter);
app.use('/api/verify-password', authLimiter);

// --- 注册 ---
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;

    const usernameErr = validateUsername(username);
    if (usernameErr) return res.status(400).json({ error: usernameErr });

    const passwordErr = validatePassword(password);
    if (passwordErr) return res.status(400).json({ error: passwordErr });

    const data = readData();
    if (data.users.find(u => u.username === username)) {
        return res.status(400).json({ error: '该用户名已被使用' });
    }

    data.users.push({
        username,
        passwordHash: sha256(password),
        createdAt: new Date().toISOString(),
        stats: { streak: 0, longestStreak: 0, totalCompleted: 0, lastCompletedDate: null, weeklyCompletions: 0 }
    });
    writeData(data);

    // 注册成功后自动颁发 Token
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({ success: true, token, user: { username, createdAt: new Date().toISOString() } });
});

// --- 登录 ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

    const data = readData();
    const user = data.users.find(u => u.username === username);

    // 不区分用户不存在和密码错误（防用户枚举）
    if (!user || sha256(password) !== user.passwordHash) {
        return res.status(401).json({ error: '用户名或密码错误' });
    }

    const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES });
    res.json({
        success: true,
        token,
        user: { username: user.username, createdAt: user.createdAt, stats: user.stats }
    });
});

// --- 验证密码（需要认证，统一错误防枚举） ---
app.post('/api/verify-password', authMiddleware, (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });

    const data = readData();
    const user = data.users.find(u => u.username === username);

    // 不区分用户不存在和密码错误（防用户枚举）
    if (!user || sha256(password) !== user.passwordHash) {
        return res.status(400).json({ error: '用户名或密码错误' });
    }
    res.json({ success: true });
});

// --- 获取用户列表（需认证，只返回可见用户） ---
app.get('/api/users', authMiddleware, (req, res) => {
    const data = readData();
    const visibleUsers = getVisibleUsers(data, req.user.username);
    res.json(data.users
        .filter(u => visibleUsers.has(u.username))
        .map(u => ({ username: u.username, createdAt: u.createdAt, stats: u.stats })));
});

// ==================== 任务 API ====================

// 获取任务（需认证，只返回可见任务）
app.get('/api/tasks', authMiddleware, (req, res) => {
    const data = readData();
    const { username, date } = req.query;
    const currentUser = req.user.username;

    // 每日任务自动生成（仅自己的）
    if (username && date && username === currentUser) {
        ensureDailyTasks(data, username, date);
        writeData(data);
    }

    let tasks = data.tasks;
    const visibleUsers = getVisibleUsers(data, currentUser);

    // 过滤：自己的任务 + 同组可见用户的公开任务
    tasks = tasks.filter(t => {
        if (t.owner === currentUser) return true;
        if (!visibleUsers.has(t.owner)) return false;
        if (t.visibility === 'private') return false;
        return true;
    });

    res.json(tasks);
});

// 获取某日每日任务（需认证）
app.get('/api/tasks/daily/:username', authMiddleware, (req, res) => {
    const data = readData();
    const { username } = req.params;
    const currentUser = req.user.username;
    const date = req.query.date || todayStr();

    // IDOR 防护：只能查看自己的每日任务
    if (username !== currentUser) {
        return res.status(403).json({ error: '无权访问他人数据' });
    }

    ensureDailyTasks(data, username, date);
    writeData(data);
    const dailyTasks = data.tasks.filter(t =>
        t.owner === username && t.dailyDate === date
    );
    res.json(dailyTasks);
});

// 添加任务（需认证，owner 强制从 Token 获取）
app.post('/api/tasks', authMiddleware, (req, res) => {
    const { title } = req.body;
    const owner = req.user.username; // 强制使用 Token 中的用户名，防止冒充
    if (!title) return res.status(400).json({ error: '标题不能为空' });

    const data = readData();
    const task = {
        id: genId(),
        title,
        description: req.body.description || '',
        tags: req.body.tags || [],
        status: req.body.status || 'in_progress',
        priorityScore: 0,
        sortOrder: Date.now(),
        deadline: req.body.deadline || null,
        timeBlock: req.body.timeBlock || null,
        owner,
        groupId: req.body.groupId || null,
        supervisor: req.body.supervisor || null,
        visibility: req.body.visibility || 'public',
        isDaily: req.body.isDaily || false,
        dailyDate: req.body.dailyDate || null,
        createdAt: new Date().toISOString(),
        completedAt: null,
    };
    task.priorityScore = calcPriority(task);

    data.tasks.push(task);
    writeData(data);
    res.json(task);
});

// 更新任务（需认证 + 权限检查）
app.put('/api/tasks/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    const data = readData();
    const task = data.tasks.find(t => t.id === id);
    if (!task) return res.status(404).json({ error: '任务不存在' });

    // IDOR 防护：只有任务所有者或组长可以修改
    if (!canModifyTask(data, id, req.user.username)) {
        return res.status(403).json({ error: '无权操作此任务' });
    }

    const allowed = ['title', 'description', 'tags', 'status', 'priorityScore', 'sortOrder', 'deadline',
        'timeBlock', 'groupId', 'supervisor', 'visibility', 'isDaily', 'dailyDate', 'completedAt'];
    allowed.forEach(k => {
        if (req.body[k] !== undefined) task[k] = req.body[k];
    });

    // 不允许通过此接口修改 owner
    if (req.body.owner !== undefined) {
        delete req.body.owner; // 静默忽略
    }

    if (req.body.status === 'done' && !task.completedAt) {
        task.completedAt = new Date().toISOString();
    }
    if (req.body.status && req.body.status !== 'done') {
        task.completedAt = null;
    }

    if (req.body.deadline !== undefined || req.body.status !== undefined || req.body.isDaily !== undefined) {
        task.priorityScore = calcPriority(task);
    }

    updateUserStats(data, task.owner);
    writeData(data);
    res.json(task);
});

// 批量排序（需认证，只排序自己的）
app.put('/api/tasks/reorder', authMiddleware, (req, res) => {
    const { tasks } = req.body;
    if (!tasks || !Array.isArray(tasks)) return res.status(400).json({ error: '无效的排序数据' });
    const data = readData();
    tasks.forEach(({ id, sortOrder }) => {
        const task = data.tasks.find(t => t.id === id);
        // 只能排序自己的任务
        if (task && task.owner === req.user.username) {
            task.sortOrder = sortOrder;
        }
    });
    writeData(data);
    res.json({ success: true });
});

// 删除任务（需认证 + 权限检查）
app.delete('/api/tasks/:id', authMiddleware, (req, res) => {
    const { id } = req.params;
    const data = readData();
    const index = data.tasks.findIndex(t => t.id === id);
    if (index === -1) return res.status(404).json({ error: '任务不存在' });

    // IDOR 防护
    if (!canModifyTask(data, id, req.user.username)) {
        return res.status(403).json({ error: '无权操作此任务' });
    }

    data.tasks.splice(index, 1);
    writeData(data);
    res.json({ success: true });
});

// 专注模式记录（需认证 + 权限检查）
app.post('/api/tasks/:id/focus', authMiddleware, (req, res) => {
    const { id } = req.params;
    const data = readData();
    const task = data.tasks.find(t => t.id === id);
    if (!task) return res.status(404).json({ error: '任务不存在' });

    if (!canModifyTask(data, id, req.user.username)) {
        return res.status(403).json({ error: '无权操作此任务' });
    }

    res.json({ success: true, message: '专注模式已开始', task: { id: task.id, title: task.title } });
});

// ==================== 小组 API ====================

// 获取所有小组（需认证，只返回自己所属的）
app.get('/api/groups', authMiddleware, (req, res) => {
    const data = readData();
    const myGroups = data.groups.filter(g =>
        g.members.find(m => m.username === req.user.username)
    );
    res.json(myGroups);
});

// 创建小组（需认证，owner 强制从 Token 获取）
app.post('/api/groups', authMiddleware, (req, res) => {
    const { name } = req.body;
    const owner = req.user.username;
    if (!name) return res.status(400).json({ error: '小组名不能为空' });
    const data = readData();
    const group = {
        id: genId(),
        name,
        owner,
        createdAt: new Date().toISOString(),
        members: [{ username: owner, role: 'owner' }],
        messages: [],
    };
    data.groups.push(group);
    writeData(data);
    res.json(group);
});

// 加入小组（需认证，只能自己加入）
app.post('/api/groups/:id/join', authMiddleware, (req, res) => {
    const { id } = req.params;
    const username = req.user.username; // 从 Token 获取，不允许冒充
    const data = readData();
    const group = data.groups.find(g => g.id === id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
    if (group.members.find(m => m.username === username)) {
        return res.status(400).json({ error: '你已在该小组中' });
    }
    group.members.push({ username, role: 'member' });
    writeData(data);
    res.json(group);
});

// 离开小组（需认证，只能自己离开）
app.post('/api/groups/:id/leave', authMiddleware, (req, res) => {
    const { id } = req.params;
    const username = req.user.username;
    const data = readData();
    const group = data.groups.find(g => g.id === id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
    if (!group.members.find(m => m.username === username)) {
        return res.status(400).json({ error: '你不在该小组中' });
    }
    group.members = group.members.filter(m => m.username !== username);
    if (group.members.length === 0) {
        data.groups = data.groups.filter(g => g.id !== id);
    } else if (group.owner === username) {
        group.owner = group.members[0].username;
        group.members[0].role = 'owner';
    }
    writeData(data);
    res.json(group);
});

// 获取小组消息（需认证，只允许成员）
app.get('/api/groups/:id/messages', authMiddleware, (req, res) => {
    const data = readData();
    const group = data.groups.find(g => g.id === req.params.id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
    if (!group.members.find(m => m.username === req.user.username)) {
        return res.status(403).json({ error: '你不是该小组成员' });
    }
    res.json(group.messages || []);
});

// 发送小组消息（需认证，from 强制从 Token 获取）
app.post('/api/groups/:id/messages', authMiddleware, (req, res) => {
    const { id } = req.params;
    const from = req.user.username;
    const { type, content } = req.body;
    if (!type || !content) return res.status(400).json({ error: '消息内容不完整' });
    const data = readData();
    const group = data.groups.find(g => g.id === id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
    if (!group.members.find(m => m.username === from)) {
        return res.status(403).json({ error: '你不是该小组成员' });
    }
    const msg = { id: genId(), from, type, content, createdAt: new Date().toISOString() };
    if (!group.messages) group.messages = [];
    group.messages.push(msg);
    writeData(data);
    res.json(msg);
});

// ==================== 每日目标 API ====================

app.post('/api/daily-goal', authMiddleware, (req, res) => {
    const username = req.user.username; // 强制从 Token 获取
    const { target } = req.body;
    if (target == null) return res.status(400).json({ error: '参数不完整' });
    const data = readData();
    const date = todayStr();
    const existing = data.dailyGoals.find(g => g.username === username && g.date === date);
    if (existing) {
        existing.target = target;
    } else {
        data.dailyGoals.push({ username, date, target });
    }
    writeData(data);
    res.json({ username, date, target });
});

app.get('/api/daily-goal/:username', authMiddleware, (req, res) => {
    // IDOR 防护：只能查看自己的
    if (req.params.username !== req.user.username) {
        return res.status(403).json({ error: '无权访问他人数据' });
    }
    const data = readData();
    const date = req.query.date || todayStr();
    const goal = data.dailyGoals.find(g => g.username === req.params.username && g.date === date);
    res.json(goal || { username: req.params.username, date, target: 0 });
});

// ==================== 每日总结 API ====================

app.post('/api/daily-summary', authMiddleware, (req, res) => {
    const username = req.user.username; // 强制从 Token 获取
    const { content, visibility } = req.body;
    if (!content) return res.status(400).json({ error: '内容不能为空' });
    const data = readData();
    const date = todayStr();
    const existing = data.dailySummaries.find(s => s.username === username && s.date === date);
    if (existing) {
        existing.content = content;
        if (visibility) existing.visibility = visibility;
        existing.createdAt = new Date().toISOString();
    } else {
        data.dailySummaries.push({
            id: genId(), username, date, content,
            visibility: visibility || 'private',
            createdAt: new Date().toISOString(),
        });
    }
    writeData(data);
    res.json({ success: true });
});

app.get('/api/daily-summary/:username', authMiddleware, (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    const summary = data.dailySummaries.find(s => s.username === req.params.username && s.date === date);

    // IDOR 防护：私人总结只能自己查看
    if (summary && summary.visibility === 'private' && req.params.username !== req.user.username) {
        return res.status(403).json({ error: '无权查看私人总结' });
    }
    // 检查是否为同组成员
    if (summary && summary.visibility !== 'private') {
        const visibleUsers = getVisibleUsers(data, req.user.username);
        if (!visibleUsers.has(req.params.username)) {
            return res.status(403).json({ error: '无权查看此总结' });
        }
    }
    res.json(summary || null);
});

// 获取公开总结列表（需认证，只返回同组成员）
app.get('/api/daily-summaries/public', authMiddleware, (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    const visibleUsers = getVisibleUsers(data, req.user.username);
    const summaries = data.dailySummaries.filter(s =>
        s.visibility === 'public' && s.date === date && visibleUsers.has(s.username)
    );
    res.json(summaries);
});

// 获取用户所有总结历史（需认证）
app.get('/api/daily-summaries/:username', authMiddleware, (req, res) => {
    let username;
    try { username = decodeURIComponent(req.params.username); } catch (e) { username = req.params.username; }

    // IDOR 防护：只能查看自己的
    if (username !== req.user.username) {
        return res.status(403).json({ error: '无权访问他人数据' });
    }

    const data = readData();
    const summaries = data.dailySummaries
        .filter(s => s.username === username)
        .sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(summaries);
});

// ==================== 打卡 API ====================

app.get('/api/checkin/:username', authMiddleware, (req, res) => {
    // IDOR 防护：只能查看自己的
    if (req.params.username !== req.user.username) {
        return res.status(403).json({ error: '无权访问他人数据' });
    }

    const data = readData();
    const date = req.query.date || todayStr();
    const completedToday = data.tasks.filter(t =>
        t.owner === req.params.username &&
        t.status === 'done' &&
        t.completedAt && t.completedAt.slice(0, 10) === date
    ).length;
    const goal = data.dailyGoals.find(g => g.username === req.params.username && g.date === date);
    const target = goal ? goal.target : 0;
    const summary = data.dailySummaries.find(s => s.username === req.params.username && s.date === date);
    const targetMet = target > 0 ? completedToday >= target : false;
    const hasSummary = !!summary;
    const checkedIn = targetMet && hasSummary;

    res.json({ username: req.params.username, date, taskCompleted: completedToday, target, targetMet, hasSummary, checkedIn });
});

app.post('/api/checkin', authMiddleware, (req, res) => {
    const username = req.user.username; // 强制从 Token 获取
    const data = readData();
    const date = todayStr();

    const completedToday = data.tasks.filter(t =>
        t.owner === username && t.status === 'done' &&
        t.completedAt && t.completedAt.slice(0, 10) === date
    ).length;
    const goal = data.dailyGoals.find(g => g.username === username && g.date === date);
    const target = goal ? goal.target : 0;
    const summary = data.dailySummaries.find(s => s.username === username && s.date === date);
    const targetMet = target > 0 ? completedToday >= target : false;
    const hasSummary = !!summary;
    const checkedIn = targetMet && hasSummary;

    const existingCI = data.checkIns.find(c => c.username === username && c.date === date);
    if (existingCI) {
        existingCI.taskCompleted = completedToday;
        existingCI.targetMet = targetMet;
        existingCI.hasSummary = hasSummary;
        existingCI.checkedIn = checkedIn;
    } else {
        data.checkIns.push({ username, date, taskCompleted: completedToday, targetMet, hasSummary, checkedIn });
    }
    writeData(data);

    if (checkedIn) {
        updateUserStats(data, username);
        writeData(data);
    }

    res.json({
        username, date, taskCompleted: completedToday, target, targetMet, hasSummary, checkedIn,
        message: checkedIn ? '🎉 打卡成功！' : (targetMet ? '还差每日总结' : (hasSummary ? '任务数量未达标' : '任务和总结都未完成'))
    });
});

// ==================== 统计 & 排行榜 API ====================

app.get('/api/stats/:username', authMiddleware, (req, res) => {
    let username;
    try { username = decodeURIComponent(req.params.username); } catch (e) { username = req.params.username; }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return res.status(404).json({ error: '用户不存在' });

    // 只能查看自己或同组成员的统计
    const visibleUsers = getVisibleUsers(data, req.user.username);
    if (!visibleUsers.has(username)) {
        return res.status(403).json({ error: '无权查看此用户统计' });
    }

    const tasks = data.tasks.filter(t => t.owner === username);
    const total = tasks.length;
    const done = tasks.filter(t => t.status === 'done').length;
    const rate = total > 0 ? Math.round((done / total) * 100) : 0;
    const today = todayStr();
    const todayDone = tasks.filter(t => t.status === 'done' && t.completedAt && t.completedAt.slice(0, 10) === today).length;
    res.json({
        username: username,
        stats: user.stats,
        total, done, completionRate: rate, todayDone,
    });
});

app.get('/api/stats/group/:groupId', authMiddleware, (req, res) => {
    const data = readData();
    const group = data.groups.find(g => g.id === req.params.groupId);
    if (!group) return res.status(404).json({ error: '小组不存在' });

    // 只允许小组成员查看
    if (!group.members.find(m => m.username === req.user.username)) {
        return res.status(403).json({ error: '你不是该小组成员' });
    }

    const memberStats = group.members.map(m => {
        const tasks = data.tasks.filter(t => t.owner === m.username && t.groupId === group.id);
        const total = tasks.length;
        const done = tasks.filter(t => t.status === 'done').length;
        const rate = total > 0 ? Math.round((done / total) * 100) : 0;
        const user = data.users.find(u => u.username === m.username);
        return { username: m.username, role: m.role, total, done, completionRate: rate, streak: user ? user.stats.streak : 0 };
    });
    const avgRate = memberStats.length > 0 ? Math.round(memberStats.reduce((s, m) => s + m.completionRate, 0) / memberStats.length) : 0;
    res.json({ groupId: group.id, groupName: group.name, avgCompletionRate: avgRate, members: memberStats });
});

app.get('/api/leaderboard', authMiddleware, (req, res) => {
    const data = readData();
    const type = req.query.type || 'personal';
    const visibleUsers = getVisibleUsers(data, req.user.username);

    if (type === 'group') {
        const myGroups = data.groups.filter(g =>
            g.members.find(m => m.username === req.user.username)
        );
        const groupStats = myGroups.map(g => {
            const memberStats = g.members.map(m => {
                const tasks = data.tasks.filter(t => t.owner === m.username && t.groupId === g.id);
                const total = tasks.length;
                const done = tasks.filter(t => t.status === 'done').length;
                return total > 0 ? Math.round((done / total) * 100) : 0;
            });
            const avgRate = memberStats.length > 0 ? Math.round(memberStats.reduce((s, r) => s + r, 0) / memberStats.length) : 0;
            return { groupId: g.id, groupName: g.name, avgCompletionRate: avgRate, memberCount: g.members.length };
        }).sort((a, b) => b.avgCompletionRate - a.avgCompletionRate);
        return res.json({ type: 'group', rankings: groupStats });
    }

    // 个人排行：只显示同组可见用户
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - now.getDay());
    weekStart.setHours(0, 0, 0, 0);

    const userStats = data.users
        .filter(u => visibleUsers.has(u.username))
        .map(u => {
            const weeklyDone = data.tasks.filter(t =>
                t.owner === u.username && t.status === 'done' &&
                t.completedAt && new Date(t.completedAt) >= weekStart
            ).length;
            const total = data.tasks.filter(t => t.owner === u.username).length;
            const done = data.tasks.filter(t => t.owner === u.username && t.status === 'done').length;
            const rate = total > 0 ? Math.round((done / total) * 100) : 0;
            return { username: u.username, weeklyDone, totalDone: done, completionRate: rate, streak: u.stats.streak || 0 };
        }).sort((a, b) => b.weeklyDone - a.weeklyDone);

    res.json({ type: 'personal', rankings: userStats });
});

// ==================== 静态文件（放在所有 API 之后） ====================
app.use(express.static(__dirname));

// ==================== 启动服务 ====================
if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
}
app.listen(PORT, () => {
    console.log(`✅ TODO LIST 服务器已启动: http://localhost:${PORT}`);
    console.log(`📁 数据目录: ${DATA_DIR}`);
    const data = readData();
    if (!data.users.length && !data.tasks.length) {
        writeData({ users: [], tasks: [], groups: [], dailyGoals: [], dailySummaries: [], checkIns: [] });
        console.log('📄 已初始化 data.json');
    }
});
