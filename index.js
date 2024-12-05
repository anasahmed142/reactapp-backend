import express from 'express';
import bcrypt from 'bcrypt';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import { Low } from 'lowdb';
import { JSONFile } from 'lowdb/node';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { nanoid } from 'nanoid'; // Use nanoid for unique ID generation

// Initialize lowdb for persistent storage
const db = new Low(new JSONFile('./database.json'), {});
await db.read();

// Ensure files and users are always initialized correctly in db.data
db.data = db.data || {}; // Make sure db.data exists
db.data.users = db.data.users || [];
db.data.files = db.data.files || []; // Ensure the files array exists

const { users, files } = db.data;

// Initialize Express app
const app = express();
// Enable CORS for all routes
const corsOptions = {
  origin: 'http://localhost:3000',  // Make sure this matches your React app's URL
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,  // Allow credentials (cookies, authorization headers, etc.)
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
// Get the current directory of the module
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Ensure the 'uploads' directory exists
const uploadDir = path.join(__dirname, 'uploads');
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

// Set up CORS and JSON middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// JWT secret key (ensure to use environment variables in production)
const jwtSecretKey = "akshdkasjdhljhqekrwoiiher234";

// Set up file storage using multer
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      const uploadDir = path.join(__dirname, 'uploads'); // Absolute path
      if (!fs.existsSync(uploadDir)) {
        fs.mkdirSync(uploadDir, { recursive: true });
      }
      cb(null, uploadDir);
    },
    filename: (req, file, cb) => {
      cb(null, Date.now() + path.extname(file.originalname));
    }
  });
  

const upload = multer({ storage });

// Auth route to register or login users
app.post("/api/auth", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(user => user.email === email);

  if (user) {
    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ message: "Invalid password" });
    } else {
      const token = jwt.sign({ email, signInTime: Date.now() }, jwtSecretKey);
      return res.status(200).json({ message: "success", token });
    }
  } else {
    const hash = await bcrypt.hash(password, 10);
    users.push({ email, password: hash });
    await db.write();

    const token = jwt.sign({ email, signInTime: Date.now() }, jwtSecretKey);
    return res.status(200).json({ message: "success", token });
  }
});

// Verify the JWT token
app.post("/api/verify", (req, res) => {
  const tokenHeaderKey = "jwt-token";
  const authToken = req.headers[tokenHeaderKey];

  if (!authToken) {
    return res.status(401).json({ status: "invalid auth", message: "No token provided" });
  }

  try {
    const verified = jwt.verify(authToken, jwtSecretKey);
    if (verified) {
      return res.status(200).json({ status: "logged in", message: "success" });
    } else {
      return res.status(401).json({ status: "invalid auth", message: "Invalid token" });
    }
  } catch (error) {
    return res.status(401).json({ status: "invalid auth", message: "Token verification failed" });
  }
});

// File upload route
app.post('/api/upload', upload.array('files'), async (req, res) => {
  const authToken = req.headers['jwt-token'];

  if (!authToken) {
    return res.status(401).json({ message: "Unauthorized. Please login." });
  }

  try {
    const verified = jwt.verify(authToken, jwtSecretKey);
    if (!verified) {
      return res.status(401).json({ message: "Invalid token" });
    }

    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ message: "No files uploaded. Please try again." });
    }

    const { files } = req;
    const { tags } = req.body;

    const fileDetails = files.map((file, index) => {
      const fileId = nanoid();
      const fileData = {
        fileId,
        filename: file.filename,
        path: file.path,
        tags: tags[index] || '',
        views: 0,
        userEmail: verified.email,
      };

      db.data.files.push(fileData);
      return {
        fileId,
        filename: file.filename,
        shareableLink: `http://localhost:3080/files/${fileId}`,
      };
    });

    await db.write();
    res.json({ success: true, files: fileDetails });
  } catch (error) {
    console.log(error);
    return res.status(500).json({ message: "Internal server error during file upload" });
  }
});

// Fetch all uploaded files
app.get('/api/files', (req, res) => {
  const authToken = req.headers['jwt-token'];

  if (!authToken) {
    return res.status(401).json({ message: "Unauthorized. Please login." });
  }

  try {
    const verified = jwt.verify(authToken, jwtSecretKey);
    if (!verified) {
      return res.status(401).json({ message: "Invalid token" });
    }

    res.json({ files });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
});

// Get uploaded files for a user
app.get('/api/get-uploaded-files', (req, res) => {
  const authToken = req.headers['jwt-token'];

  if (!authToken) {
    return res.status(401).json({ message: "Unauthorized. Please login." });
  }

  try {
    const verified = jwt.verify(authToken, jwtSecretKey);
    if (!verified) {
      return res.status(401).json({ message: "Invalid token" });
    }

    const userFiles = files.filter(file => file.userEmail === verified.email); // Filter by user email
    const fileDetails = userFiles.map(file => ({
      fileId: file.fileId,
      filename: file.filename,
      shareableLink: `http://localhost:3080/files/${file.fileId}`,
    }));

    res.json({ success: true, files: fileDetails });
  } catch (error) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
});
// Publicly accessible files (by fileId)
app.get('/api/files/:fileId', (req, res) => {
  const { fileId } = req.params;
  const file = files.find(file => file.fileId === fileId);

  if (!file) {
    return res.status(404).json({ message: "File not found" });
  }

  file.views += 1;  // Increment view count
  db.write();

  res.json({
    message: "File accessed",
    file: {
      filename: file.filename,
      views: file.views,
      path: `/uploads/${file.filename}`, // Correct file path for the frontend to access
    }
  });
});

// Get public files (if needed)
app.get('/api/public-files', (req, res) => {
  res.json({ files });
});

// Start the server
const port = 3080;
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
