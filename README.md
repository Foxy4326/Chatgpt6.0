// === DEPENDÊNCIAS ===
const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const { OpenAI } = require('openai');

// === CONFIGURAÇÕES ===
const app = express();
const PORT = 3000;
const JWT_SECRET = 'chave_secreta_super_secreta_123!';
const DB_PATH = './database.sqlite';
const IMAGES_DIR = path.join(__dirname, 'public/images');

// 🔑 Substitua pela sua chave da OpenAI!
const OPENAI_API_KEY = 'SUA_CHAVE_AQUI'; // ←←← ALTERE ISSO!

if (OPENAI_API_KEY === 'SUA_CHAVE_AQUI') {
  console.error('❌ ERRO: Você precisa colocar sua chave da OpenAI no código!');
  console.error('Vá em https://platform.openai.com/api-keys e cole aqui.');
  process.exit(1);
}

const openai = new OpenAI({ apiKey: OPENAI_API_KEY });

// Criar pastas
if (!fs.existsSync('./public')) fs.mkdirSync('./public');
if (!fs.existsSync(IMAGES_DIR)) fs.mkdirSync(IMAGES_DIR, { recursive: true });

// === BANCO DE DADOS ===
const db = new sqlite3.Database(DB_PATH);

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS images (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    userId INTEGER,
    text TEXT,
    imagePath TEXT,
    createdAt DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(userId) REFERENCES users(id)
  )`);
});

// === MIDDLEWARES ===
app.use(cors());
app.use(express.json());
app.use('/images', express.static(IMAGES_DIR));

// === FUNÇÃO DE AUTENTICAÇÃO ===
function auth(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Token necessário' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Token inválido' });
  }
}

// === ROTAS ===

// Registro
app.post('/api/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Usuário e senha obrigatórios' });
  try {
    const hashed = await bcrypt.hash(password, 10);
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashed], function(err) {
      if (err && err.message.includes('UNIQUE')) return res.status(400).json({ error: 'Usuário já existe' });
      if (err) return res.status(500).json({ error: 'Erro ao registrar' });
      res.status(201).json({ message: 'Usuário criado com sucesso!' });
    });
  } catch (err) {
    res.status(500).json({ error: 'Erro interno' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user) return res.status(401).json({ error: 'Credenciais inválidas' });
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(401).json({ error: 'Credenciais inválidas' });
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1d' });
    res.json({ token, username: user.username });
  });
});

// Gerar imagem com DALL·E 3 (IA REAL!)
app.post('/api/ia/generate', auth, async (req, res) => {
  const { text } = req.body;
  if (!text || typeof text !== 'string' || text.trim().length < 5) {
    return res.status(400).json({ error: 'Texto inválido (mínimo 5 caracteres)' });
  }

  try {
    // Chamar a API do DALL·E 3
    const response = await openai.images.generate({
      model: "dall-e-3",
      prompt: text,
      n: 1,
      size: "1024x1024",
    });

    const imageUrl = response.data[0].url;
    const imageResponse = await fetch(imageUrl);
    const arrayBuffer = await imageResponse.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    // Salvar imagem localmente
    const filename = `dalle_${Date.now()}.png`;
    const filepath = path.join(IMAGES_DIR, filename);
    fs.writeFileSync(filepath, buffer);

    // Salvar no banco
    db.run(
      'INSERT INTO images (userId, text, imagePath) VALUES (?, ?, ?)',
      [req.user.id, text, `/images/${filename}`],
      function(err) {
        if (err) return res.status(500).json({ error: 'Erro ao salvar imagem no histórico' });
        res.json({ imagePath: `/images/${filename}` });
      }
    );
  } catch (err) {
    console.error('Erro na IA:', err.message || err);
    res.status(500).json({ error: 'Falha ao gerar imagem com IA. Tente outro texto.' });
  }
});

// Histórico do usuário
app.get('/api/ia/history', auth, (req, res) => {
  db.all('SELECT * FROM images WHERE userId = ? ORDER BY createdAt DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Erro ao carregar histórico' });
    res.json(rows);
  });
});

// === FRONTEND (MESMO DO ANTERIOR) ===
const FRONTEND_HTML = `
<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <title>IA Geradora de Imagens (DALL·E 3)</title>
  <style>
    body { font-family: Arial, sans-serif; background: #f9f9f9; padding: 20px; }
    .container { max-width: 800px; margin: 0 auto; }
    input, textarea, button {
      width: 100%; padding: 10px; margin: 8px 0; box-sizing: border-box;
    }
    button { background: #4CAF50; color: white; border: none; cursor: pointer; }
    button:hover { opacity: 0.9; }
    #ia-section { display: none; }
    .history-item { margin: 20px 0; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
    img { max-width: 100%; margin-top: 10px; border: 1px solid #ddd; border-radius: 4px; }
    h1 { text-align: center; color: #333; }
    .error { background: #ffebee; color: #c62828; padding: 10px; border-radius: 4px; margin: 10px 0; }
  </style>
</head>
<body>
  <div class="container">
    <h1>🎨 IA Geradora de Imagens (DALL·E 3)</h1>

    <div id="auth-section">
      <input type="text" id="username" placeholder="Usuário" />
      <input type="password" id="password" placeholder="Senha" />
      <button onclick="register()">Registrar</button>
      <button onclick="login()">Login</button>
    </div>

    <div id="ia-section">
      <h2>Bem-vindo, <span id="user-display"></span>!</h2>
      <textarea id="textInput" placeholder="Descreva uma imagem (ex: 'um gato astronauta na lua, estilo cartoon')"></textarea>
      <button onclick="generateImage()">Gerar Imagem com IA</button>
      <div id="status"></div>

      <h3>🖼️ Histórico de Imagens</h3>
      <div id="history"></div>
    </div>
  </div>

  <script>
    let token = localStorage.getItem('token');
    let username = localStorage.getItem('username');

    if (token && username) {
      showIASection(username);
      loadHistory();
    }

    function showStatus(msg, isError = false) {
      const div = document.getElementById('status');
      div.className = isError ? 'error' : '';
      div.textContent = msg;
      setTimeout(() => { if (!isError) div.textContent = ''; }, 5000);
    }

    async function register() {
      const user = document.getElementById('username').value;
      const pass = document.getElementById('password').value;
      if (!user || !pass) return showStatus('Preencha todos os campos', true);
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
      });
      const data = await res.json();
      showStatus(data.message || data.error || 'Erro desconhecido', !data.message);
    }

    async function login() {
      const user = document.getElementById('username').value;
      const pass = document.getElementById('password').value;
      if (!user || !pass) return showStatus('Preencha todos os campos', true);
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: user, password: pass })
      });
      const data = await res.json();
      if (data.token) {
        localStorage.setItem('token', data.token);
        localStorage.setItem('username', data.username);
        showIASection(data.username);
        loadHistory();
        showStatus('Login bem-sucedido!');
      } else {
        showStatus(data.error || 'Login falhou', true);
      }
    }

    function showIASection(user) {
      document.getElementById('auth-section').style.display = 'none';
      document.getElementById('ia-section').style.display = 'block';
      document.getElementById('user-display').textContent = user;
    }

    async function generateImage() {
      const text = document.getElementById('textInput').value.trim();
      if (!text || text.length < 5) return showStatus('Digite uma descrição com pelo menos 5 caracteres', true);
      
      showStatus('Gerando imagem com IA... (pode levar 10-20 segundos)');
      const res = await fetch('/api/ia/generate', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + token
        },
        body: JSON.stringify({ text })
      });
      const data = await res.json();
      if (data.imagePath) {
        showStatus('Imagem gerada com sucesso!');
        loadHistory();
      } else {
        showStatus(data.error || 'Falha ao gerar imagem', true);
      }
    }

    async function loadHistory() {
      const res = await fetch('/api/ia/history', {
        headers: { 'Authorization': 'Bearer ' + token }
      });
      const images = await res.json();
      const div = document.getElementById('history');
      div.innerHTML = images.length === 0 
        ? '<p>Nenhuma imagem gerada ainda.</p>'
        : images.map(img => 
            '<div class="history-item">' +
              '<p><strong>Texto:</strong> ' + img.text + '</p>' +
              '<img src="' + img.imagePath + '" alt="Imagem gerada" />' +
            '</div>'
          ).join('');
    }
  </script>
</body>
</html>
`;

app.get('/', (req, res) => {
  res.send(FRONTEND_HTML);
});

// === INICIAR SERVIDOR ===
app.listen(PORT, () => {
  console.log(`✅ Servidor rodando em http://localhost:${PORT}`);
  console.log(`🧠 Usando DALL·E 3 da OpenAI`);
  console.log(`📁 Banco: ${DB_PATH} | Imagens: ${IMAGES_DIR}`);
});
