const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');

// 解析 JSON body
app.use(express.json());

// 托管静态文件（前端 HTML/CSS/JS）
app.use(express.static(__dirname));

// ==================== 数据读写 ====================
function readData() {
    try {
        if (!fs.existsSync(DATA_FILE)) {
            fs.writeFileSync(DATA_FILE, JSON.stringify({ users: [], tasks: [] }, null, 2));
        }
        const raw = fs.readFileSync(DATA_FILE, 'utf-8');
        return JSON.parse(raw);
    } catch (e) {
        return { users: [], tasks: [] };
    }
}

function writeData(data) {
    fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}

function sha256(text) {
    return crypto.createHash('sha256').update(text).digest('hex');
}

// ==================== API 路由 ====================

// 注册
app.post('/api/register', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }
    if (username.length < 2) {
        return res.status(400).json({ error: '用户名至少2个字符' });
    }
    if (password.length < 3) {
        return res.status(400).json({ error: '密码至少3位' });
    }

    const data = readData();
    if (data.users.find(u => u.username === username)) {
        return res.status(400).json({ error: '该用户名已被使用' });
    }

    const user = {
        username,
        passwordHash: sha256(password),
        createdAt: new Date().toISOString()
    };
    data.users.push(user);
    writeData(data);

    res.json({ success: true, user: { username: user.username, createdAt: user.createdAt } });
});

// 登录
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ error: '用户不存在，请先注册' });
    }

    const hash = sha256(password);
    if (hash !== user.passwordHash) {
        return res.status(400).json({ error: '密码错误' });
    }

    res.json({ success: true, user: { username: user.username, createdAt: user.createdAt } });
});

// 验证密码（用于修改他人任务时验证）
app.post('/api/verify-password', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ error: '用户名和密码不能为空' });
    }

    const data = readData();
    const user = data.users.find(u => u.username === username);
    if (!user) {
        return res.status(400).json({ error: '用户不存在' });
    }

    const hash = sha256(password);
    if (hash !== user.passwordHash) {
        return res.status(400).json({ error: '密码错误' });
    }

    res.json({ success: true });
});

// 获取所有用户列表（用于快速登录和筛选）
app.get('/api/users', (req, res) => {
    const data = readData();
    const users = data.users.map(u => ({ username: u.username, createdAt: u.createdAt }));
    res.json(users);
});

// 获取所有任务
app.get('/api/tasks', (req, res) => {
    const data = readData();
    res.json(data.tasks);
});

// 添加任务
app.post('/api/tasks', (req, res) => {
    const { title, desc, deadline, owner } = req.body;
    if (!title || !owner) {
        return res.status(400).json({ error: '标题和创建者不能为空' });
    }

    const data = readData();
    const task = {
        id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
        title,
        desc: desc || '',
        deadline: deadline || null,
        completed: false,
        owner,
        createdAt: new Date().toISOString(),
        completedAt: null,
        sortOrder: Date.now(),
    };

    data.tasks.push(task);
    writeData(data);
    res.json(task);
});

// 更新任务（切换完成状态、修改内容等）
app.put('/api/tasks/:id', (req, res) => {
    const { id } = req.params;
    const data = readData();
    const task = data.tasks.find(t => t.id === id);

    if (!task) {
        return res.status(404).json({ error: '任务不存在' });
    }

    // 允许更新的字段
    const { completed, title, desc, deadline, sortOrder, completedAt } = req.body;
    if (completed !== undefined) task.completed = completed;
    if (title !== undefined) task.title = title;
    if (desc !== undefined) task.desc = desc;
    if (deadline !== undefined) task.deadline = deadline;
    if (sortOrder !== undefined) task.sortOrder = sortOrder;
    if (completedAt !== undefined) task.completedAt = completedAt;

    writeData(data);
    res.json(task);
});

// 更新多个任务的排序（批量）
app.put('/api/tasks/reorder', (req, res) => {
    const { tasks } = req.body; // [{ id, sortOrder }, ...]
    if (!tasks || !Array.isArray(tasks)) {
        return res.status(400).json({ error: '无效的排序数据' });
    }

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

    if (index === -1) {
        return res.status(404).json({ error: '任务不存在' });
    }

    data.tasks.splice(index, 1);
    writeData(data);
    res.json({ success: true });
});

// ==================== 启动服务 ====================
app.listen(PORT, () => {
    console.log(`✅ TODO LIST 服务器已启动: http://localhost:${PORT}`);
    // 确保数据文件存在
    if (!fs.existsSync(DATA_FILE)) {
        writeData({ users: [], tasks: [] });
        console.log('📄 已创建 data.json');
    }
});
