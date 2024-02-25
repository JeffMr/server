const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const session = require('express-session'); // Adicionado

const app = express();
const port = 3000;

/********** Código adicionado*****/
// Configurar o Express para usar o EJS como mecanismo de modelo
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views')); // Diretório onde seus arquivos de visualização serão armazenados
/********** Fim do  Código adicionado******/

app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));

// Configurar sessão
app.use(session({
    secret: 'suaChaveSecreta',
    resave: false,
    saveUninitialized: true
}));

const db = new sqlite3.Database('./database.sqlite3');

// Função para criar um hash seguro da senha
const hashPassword = async (password) => {
    try {
        const saltRounds = 10; // Número de rounds de sal (custo do algoritmo de hash)
        const hash = await bcrypt.hash(password, saltRounds);
        return hash;
    } catch (error) {
        throw new Error('Erro ao criar hash da senha');
    }
};

// Função para verificar se a senha corresponde ao hash
const comparePasswords = async (password, hash) => {
    try {
        const match = await bcrypt.compare(password, hash);
        return match;
    } catch (error) {
        console.log('Erro ao comparar senha:', error);
        throw new Error('Erro ao comparar senha');
    }
};

// Rota para a raiz do aplicativo, renderizando a página de login
app.get('/', (req, res) => {
    res.render('login'); // Renderiza a página de login (login.ejs)
});

// Rota para renderizar a página de cadastro
app.get('/cadastro', (req, res) => {
    res.render('cadastro'); // Renderiza a página de cadastro (cadastro.ejs)
});

// Endpoint de Cadastro
app.post('/cadastro', async (req, res) => {
    const { name, email, password } = req.body;

    try {
        // Criptografar a senha antes de armazená-la no banco de dados
        const hashedPassword = await hashPassword(password);
        
        // Inserir novo usuário no banco de dados com a senha criptografada
        db.run('INSERT INTO Usuario (Name, Email, Password) VALUES (?, ?, ?)', [name, email, hashedPassword], (err) => {
            if (err) {
                res.status(500).send(err.message);
            } else {
                // Redirecionar para a página de login após cadastro bem-sucedido
                res.redirect('/');
            }
        });
    } catch (error) {
        res.status(500).send(error.message);
    }
});

// Endpoint de Login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    // Verificar se o email está cadastrado no banco de dados
    db.get('SELECT * FROM Usuario WHERE Email = ?', [email], async (err, row) => {
        if (err) {
            res.status(500).send(err.message);
        } else if (!row) {
            res.status(400).send('Email não encontrado');
        } else {
            try {
                // Verificar se a senha fornecida corresponde à senha armazenada no banco de dados
                const passwordMatch = await comparePasswords(password, row.Password);
                if (passwordMatch) {
                    // Autenticação bem-sucedida
                    // Salvar o usuário na sessão
                    req.session.user = row;
                    res.redirect('/dashboard');
                } else {
                    res.status(400).send('Senha incorreta');
                }
            } catch (error) {
                res.status(500).send(error.message);
            }
        }
    });
});


// Endpoint do Dashboard
app.get('/dashboard', (req, res) => {
    // Verifique se o usuário está autenticado
    if (!req.session || !req.session.user) {
        res.redirect('/'); // Redireciona para a página de login se o usuário não estiver autenticado
    } else {
        // Recuperar os dados do usuário do banco de dados
        const userId = req.session.user.ID; // Corrigido para acessar o ID do usuário
        db.get('SELECT * FROM Usuario WHERE ID = ?', [userId], (err, row) => {
            if (err) {
                res.status(500).send(err.message);
            } else {
                // Renderizar o modelo do EJS do dashboard com os dados do usuário
                res.render('dashboard', { user: row });
            }
        });
    }
});

// Endpoint de logout
app.get('/logout', (req, res) => {
    // Destruir a sessão do usuário
    req.session.destroy((err) => {
        if (err) {
            console.error('Erro ao encerrar a sessão:', err);
            res.status(500).send('Erro ao encerrar a sessão');
        } else {
            // Redirecionar o usuário de volta para a página de login
            res.redirect('/');
        }
    });
});



app.listen(port, () => {
    console.log(`Server is running on http://localhost:${port}`);
});

