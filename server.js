import express from "express";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const app = express();
app.use(express.json());

const users = [];

// Dados iniciais mockados:
const alunos = [
  { id: 1, nome: "Ana Souza",   ra: "SC3001", nota1: 8.0, nota2: 7.0 },
  { id: 2, nome: "Bruno Lima",  ra: "SC3002", nota1: 5.0, nota2: 4.5 },
  { id: 3, nome: "Carla Dias",  ra: "SC3003", nota1: 6.0, nota2: 6.0 },
  { id: 4, nome: "Diego Alves", ra: "SC3004", nota1: 9.5, nota2: 8.0 },
];

const media = (a) => (a.nota1 + a.nota2) / 2;

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: "Informe username e password." });
  }
  if (users.find((u) => u.username === username)) {
    return res.status(409).json({ message: "Usuário já existe." });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  users.push({ username, password: hashedPassword });

  res.status(201).json({ message: "User registered" });
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  const user = users.find((u) => u.username === username);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ message: "Login Incorreto!" });
  }

  const token = jwt.sign(
    { username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: "1h", algorithm: "HS256" }
  );

  res.json({ token });
});

const authenticateJWT = (req, res, next) => {
  const authHeader = req.header("Authorization");
  let token;

  if (authHeader) {
    const parts = authHeader.split(" ");
    if (parts.length === 2) token = parts[1];
  }

  if (!token) {
    return res.status(401).json({ message: "Acesso negado. Token não fornecido." });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === "TokenExpiredError") {
        return res.status(401).json({ message: "Acesso negado. Token expirado." });
      }
      return res.status(403).json({ message: "Acesso negado. Token inválido." });
    }
    req.user = user;
    next();
  });
};

app.use(authenticateJWT);

app.get("/alunos", (req, res) => {
  res.json(alunos);
});

app.get("/alunos/medias", (req, res) => {
  res.json(alunos.map((a) => ({ nome: a.nome, media: media(a) })));
});

app.get("/alunos/aprovados", (req, res) => {
  res.json(
    alunos.map((a) => ({
      nome: a.nome,
      status: media(a) >= 6 ? "aprovado" : "reprovado",
    }))
  );
});

app.get("/alunos/:id", (req, res) => {
  const aluno = alunos.find((a) => a.id === Number(req.params.id));
  if (!aluno) return res.status(404).json({ message: "Aluno não encontrado!" });
  res.json(aluno);
});

app.post("/alunos", (req, res) => {
  const { id, nome, ra, nota1, nota2 } = req.body;

  if (id === undefined || !nome || !ra || nota1 === undefined || nota2 === undefined) {
    return res.status(400).json({ message: "Informe id, nome, ra, nota1 e nota2." });
  }
  if (alunos.find((a) => a.id === Number(id))) {
    return res.status(409).json({ message: "Já existe aluno com esse id." });
  }

  const novo = { id: Number(id), nome, ra, nota1: Number(nota1), nota2: Number(nota2) };
  alunos.push(novo);
  res.status(201).json(novo);
});

app.put("/alunos/:id", (req, res) => {
  const aluno = alunos.find((a) => a.id === Number(req.params.id));
  if (!aluno) return res.status(404).json({ message: "Aluno não encontrado!" });

  const { nome, ra, nota1, nota2 } = req.body;
  if (nome !== undefined) aluno.nome = nome;
  if (ra !== undefined) aluno.ra = ra;
  if (nota1 !== undefined) aluno.nota1 = Number(nota1);
  if (nota2 !== undefined) aluno.nota2 = Number(nota2);

  res.json(aluno);
});

app.delete("/alunos/:id", (req, res) => {
  const i = alunos.findIndex((a) => a.id === Number(req.params.id));
  if (i === -1) return res.status(404).json({ message: "Aluno não encontrado!" });

  alunos.splice(i, 1);
  res.json({ message: "Aluno apagado com sucesso!" });
});



app.listen(3000, () => {
  console.log("Servidor ativo e aguardando requisições...");
});