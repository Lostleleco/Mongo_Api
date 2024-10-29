const express = require('express');
const bodyParser = require('body-parser');
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const multer = require('multer');
require('dotenv').config();

const aws = require('aws-sdk');
const multerS3 = require('multer-s3');

// Configurar o S3
aws.config.update({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION
});

const s3 = new aws.S3();

// Configurar multer para usar o S3
const upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: process.env.S3_BUCKET_NAME,
        key: function (req, file, cb) {
            cb(null, `uploads/${Date.now().toString()}-${file.originalname}`); // Definindo o nome do arquivo
        }
    })
});

const app = express();
app.use(bodyParser.json());

// MongoDB setup
const uri = process.env.MONGODB_URI; // Use a variável de ambiente
const client = new MongoClient(uri);
let db;

// Conectar ao MongoDB
async function connectDB() {
    try {
        await client.connect();
        db = client.db('project0'); // Use o nome do seu banco de dados
        console.log("Conectado ao MongoDB");

        // Criar usuário administrador se não existir
        await createAdminUser();
    } catch (error) {
        console.error("Erro ao conectar ao MongoDB:", error);
    }
}

// Função para criar um usuário administrador
async function createAdminUser() {
    const adminUsername = 'Eliane_Braga';
    const adminPassword = 'Fs50705969';
    const hashedPassword = await bcrypt.hash(adminPassword, 10);

    const existingUser = await db.collection('users').findOne({ username: adminUsername });
    if (!existingUser) {
        await db.collection('users').insertOne({
            username: adminUsername,
            password: hashedPassword,
            isAdmin: true // Marque como administrador
        });
        console.log('Usuário administrador criado com sucesso!');
    } else {
        console.log('Usuário administrador já existe!');
    }
}

connectDB();

// Middleware para autenticação de token
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) {
        return res.status(403).send('Acesso negado!');
    }

    jwt.verify(token.split(' ')[1], process.env.JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).send('Token inválido!');
        }
        req.user = user; // Adiciona o usuário à requisição
        next();
    });
};

// Middleware para autenticação de administrador
const authenticateAdmin = (req, res, next) => {
    if (!req.user || !req.user.isAdmin) {
        return res.status(403).send('Acesso negado! Você precisa ser um administrador.');
    }
    next();
};

// Rota de login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await db.collection('users').findOne({ username });
    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign({ id: user._id, isAdmin: user.isAdmin }, process.env.JWT_SECRET, { expiresIn: '1h' });
        return res.json({ token });
    }
    res.status(401).send('Credenciais inválidas');
});

// Rota para registrar usuário
app.post('/register', async (req, res) => {
    const { username, password, isAdmin } = req.body; // Adicionando isAdmin
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.collection('users').insertOne({
        username,
        password: hashedPassword,
        isAdmin: isAdmin || false // Define como false se não for especificado
    });
    res.send('Usuário registrado');
});

// Rota para inserir produto (apenas para administradores)
app.post('/produtos', authenticateToken, authenticateAdmin, upload.single('image'), async (req, res) => {
    const { name, description, price } = req.body; 
    const image = req.file.location; // URL da imagem no S3
    await db.collection('produtos').insertOne({ name, description, price, image });
    res.send('Produto inserido');
});

// Rota para deletar produto (apenas para administradores)
app.delete('/produtos/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    const id = req.params.id;
    await db.collection('produtos').deleteOne({ _id: new MongoClient.ObjectId(id) });
    res.send('Produto deletado');
});

// Rota para atualizar produto (apenas para administradores)
app.put('/produtos/:id', authenticateToken, authenticateAdmin, async (req, res) => {
    const id = req.params.id;
    const { name, description, price } = req.body;
    await db.collection('produtos').updateOne(
        { _id: new MongoClient.ObjectId(id) },
        { $set: { name, description, price } }
    );
    res.send('Produto atualizado');
});

// Iniciar o servidor
app.listen(3000, () => {
    console.log("Servidor rodando na porta 3000");
});
