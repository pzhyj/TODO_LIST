const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
// 生产环境使用 Render 持久磁盘，本地开发使用项目目录
const DATA_DIR = process.env.DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');

app.use(express.json());

// ==================== 数据读写 ====================
function readData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            writeData({ users: [], tasks: [], groups: [], dailyGoals: [], dailySummaries: [], checkIns: [] });
        }
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        const data = JSON.parse(raw);
        // 向后兼容：确保新字段存在
        if (!data.groups) data.groups = [];
        if (!data.dailyGoals) data.dailyGoals = [];
        if (!data.dailySummaries) data.dailySummaries = [];
        if (!data.checkIns) data.checkIns = [];
        // 升级旧任务格式
        data.tasks = data.tasks.map(t => ({
            title: '', description: '', tags: [], status: 'todo',
            priorityScore: 0, sortOrder: Date.now(), deadline: null,
            timeBlock: null, owner: '', groupId: null, supervisor: null,
            visibility: 'public', isDaily: false, dailyDate: null,
            createdAt: new Date().toISOString(), completedAt: null,
            ...t
        }));
        // 升级旧用户格式
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
    // 本周完成数
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

// ==================== 鉴权中间件（简单） ====================
// 不强制鉴权，但校验密码的操作在各端点内处理

// ==================== API 路由 ====================

// --- 注册 ---
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    if (username.length < 2) return res.status(400).json({ error: '用户名至少2个字符' });
    if (password.length < 3) return res.status(400).json({ error: '密码至少3位' });

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
    res.json({ success: true, user: { username, createdAt: new Date().toISOString() } });
});

// --- 登录 ---
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: '用户不存在，请先注册' });
    if (sha256(password) !== user.passwordHash) return res.status(400).json({ error: '密码错误' });
    res.json({ success: true, user: { username: user.username, createdAt: user.createdAt, stats: user.stats } });
});

// --- 验证密码 ---
app.post('/api/verify-password', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: '用户名和密码不能为空' });
    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return res.status(400).json({ error: '用户不存在' });
    if (sha256(password) !== user.passwordHash) return res.status(400).json({ error: '密码错误' });
    res.json({ success: true });
});

// --- 获取用户列表 ---
app.get('/api/users', (req, res) => {
    const data = readData();
    res.json(data.users.map(u => ({ username: u.username, createdAt: u.createdAt, stats: u.stats })));
});

// ==================== 任务 API ====================

// 获取任务（支持筛选）
app.get('/api/tasks', (req, res) => {
    const data = readData();
    const { username, date } = req.query;

    // 如果是请求某用户的每日任务，先自动生成
    if (username && date) {
        ensureDailyTasks(data, username, date);
        writeData(data);
    }

    let tasks = data.tasks;
    res.json(tasks);
});

// 获取某日每日任务
app.get('/api/tasks/daily/:username', (req, res) => {
    const data = readData();
    const { username } = req.params;
    const date = req.query.date || todayStr();
    ensureDailyTasks(data, username, date);
    writeData(data);
    const dailyTasks = data.tasks.filter(t =>
        t.owner === username && t.dailyDate === date
    );
    res.json(dailyTasks);
});

// 添加任务
app.post('/api/tasks', (req, res) => {
    const { title, owner } = req.body;
    if (!title || !owner) return res.status(400).json({ error: '标题和创建者不能为空' });

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

// 更新任务
app.put('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    const data = readData();
    const task = data.tasks.find(t => t.id === id);
    if (!task) return res.status(404).json({ error: '任务不存在' });

    const allowed = ['title','description','tags','status','priorityScore','sortOrder','deadline',
        'timeBlock','groupId','supervisor','visibility','isDaily','dailyDate','completedAt'];
    allowed.forEach(k => {
        if (req.body[k] !== undefined) task[k] = req.body[k];
    });

    // 如果标记完成
    if (req.body.status === 'done' && !task.completedAt) {
        task.completedAt = new Date().toISOString();
    }
    if (req.body.status && req.body.status !== 'done') {
        task.completedAt = null;
    }

    // 重新计算优先级
    if (req.body.deadline !== undefined || req.body.status !== undefined || req.body.isDaily !== undefined) {
        task.priorityScore = calcPriority(task);
    }

    updateUserStats(data, task.owner);
    writeData(data);
    res.json(task);
});

// 批量排序
app.put('/api/tasks/reorder', (req, res) => {
    const { tasks } = req.body;
    if (!tasks || !Array.isArray(tasks)) return res.status(400).json({ error: '无效的排序数据' });
    const data = readData();
    tasks.forEach(({ id, sortOrder }) => {
        const task = data.tasks.find(t => t.id === id);
        if (task) task.sortOrder = sortOrder;
    });
    writeData(data);
    res.json({ success: true });
});

// 删除任务
app.delete('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    const data = readData();
    const index = data.tasks.findIndex(t => t.id === id);
    if (index === -1) return res.status(404).json({ error: '任务不存在' });
    data.tasks.splice(index, 1);
    writeData(data);
    res.json({ success: true });
});

// 专注模式记录
app.post('/api/tasks/:id/focus', (req, res) => {
    const { id } = req.params;
    const data = readData();
    const task = data.tasks.find(t => t.id === id);
    if (!task) return res.status(404).json({ error: '任务不存在' });
    // 记录专注开始（可扩展存储专注时长）
    res.json({ success: true, message: '专注模式已开始', task: { id: task.id, title: task.title } });
});

// ==================== 小组 API ====================

// 获取所有小组
app.get('/api/groups', (req, res) => {
    const data = readData();
    res.json(data.groups);
});

// 创建小组
app.post('/api/groups', (req, res) => {
    const { name, owner } = req.body;
    if (!name || !owner) return res.status(400).json({ error: '小组名和创建者不能为空' });
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

// 加入小组
app.post('/api/groups/:id/join', (req, res) => {
    const { id } = req.params;
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: '用户名不能为空' });
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

// 离开小组
app.post('/api/groups/:id/leave', (req, res) => {
    const { id } = req.params;
    const { username } = req.body;
    const data = readData();
    const group = data.groups.find(g => g.id === id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
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

// 获取小组消息
app.get('/api/groups/:id/messages', (req, res) => {
    const data = readData();
    const group = data.groups.find(g => g.id === req.params.id);
    if (!group) return res.status(404).json({ error: '小组不存在' });
    res.json(group.messages || []);
});

// 发送小组消息
app.post('/api/groups/:id/messages', (req, res) => {
    const { id } = req.params;
    const { from, type, content } = req.body;
    if (!from || !type || !content) return res.status(400).json({ error: '消息内容不完整' });
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

app.post('/api/daily-goal', (req, res) => {
    const { username, target } = req.body;
    if (!username || target == null) return res.status(400).json({ error: '参数不完整' });
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

app.get('/api/daily-goal/:username', (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    const goal = data.dailyGoals.find(g => g.username === req.params.username && g.date === date);
    res.json(goal || { username: req.params.username, date, target: 0 });
});

// ==================== 每日总结 API ====================

app.post('/api/daily-summary', (req, res) => {
    const { username, content, visibility } = req.body;
    if (!username || !content) return res.status(400).json({ error: '参数不完整' });
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

app.get('/api/daily-summary/:username', (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    const summary = data.dailySummaries.find(s => s.username === req.params.username && s.date === date);
    res.json(summary || null);
});

// 获取公开总结列表（小组内可见）
app.get('/api/daily-summaries/public', (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    const summaries = data.dailySummaries.filter(s => s.visibility === 'public' && s.date === date);
    res.json(summaries);
});

// 获取用户所有总结历史
app.get('/api/daily-summaries/:username', (req, res) => {
    let username;
    try { username = decodeURIComponent(req.params.username); } catch (e) { username = req.params.username; }
    const data = readData();
    const summaries = data.dailySummaries
        .filter(s => s.username === username)
        .sort((a, b) => new Date(b.date) - new Date(a.date));
    res.json(summaries);
});

// ==================== 打卡 API ====================

app.get('/api/checkin/:username', (req, res) => {
    const data = readData();
    const date = req.query.date || todayStr();
    // 计算当日任务完成数
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

app.post('/api/checkin', (req, res) => {
    const { username } = req.body;
    if (!username) return res.status(400).json({ error: '用户名不能为空' });
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

    // 保存打卡记录
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

    res.json({ username, date, taskCompleted: completedToday, target, targetMet, hasSummary, checkedIn,
        message: checkedIn ? '🎉 打卡成功！' : (targetMet ? '还差每日总结' : (hasSummary ? '任务数量未达标' : '任务和总结都未完成'))
    });
});

// ==================== 统计 & 排行榜 API ====================

app.get('/api/stats/:username', (req, res) => {
    let username;
    try { username = decodeURIComponent(req.params.username); } catch (e) { username = req.params.username; }
    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) return res.status(404).json({ error: '用户不存在' });
    const tasks = data.tasks.filter(t => t.owner === username);
    const total = tasks.length;
    const done = tasks.filter(t => t.status === 'done').length;
    const rate = total > 0 ? Math.round((done / total) * 100) : 0;
    const today = todayStr();
    const todayDone = tasks.filter(t => t.status === 'done' && t.completedAt && t.completedAt.slice(0, 10) === today).length;
    res.json({
        username: username,
        stats: user.stats,
        total,
        done,
        completionRate: rate,
        todayDone,
    });
});

app.get('/api/stats/group/:groupId', (req, res) => {
    const data = readData();
    const group = data.groups.find(g => g.id === req.params.groupId);
    if (!group) return res.status(404).json({ error: '小组不存在' });
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

app.get('/api/leaderboard', (req, res) => {
    const data = readData();
    const type = req.query.type || 'personal';

    if (type === 'group') {
        const groupStats = data.groups.map(g => {
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

    // 个人排行：本周完成任务数
    const now = new Date();
    const weekStart = new Date(now);
    weekStart.setDate(now.getDate() - now.getDay());
    weekStart.setHours(0, 0, 0, 0);

    const userStats = data.users.map(u => {
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
// 确保数据目录存在（Render 持久磁盘挂载时不会自动创建）
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
