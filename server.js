//import
const express = require('express');   // express for creating our server
const bcrypt = require('bcrypt');  // for password hashing
const jwt = require('jsonwebtoken');  // for generating & verifying JWT token

//create express app
const app = express();

const PORT = process.env.PORT || 3000; //specifying the port on which my server will listen
const SECRET_KEY = 'your_secret_key';   //change this to  a strong key

//to configure express to automatically parse JSON request bodies
app.use(express.json());

//mock database
const users = []; // Change 'user' to 'users'

// Register endpoint
app.post('/register', async (req, res) => { 
    const { username, password } = req.body;

    // Check if the user already exists
    if (users.find(user => user.username === username)) {
        return res.status(400).json({ message: "User already exists" });
    }

    try {
        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);
        // Store the user
        users.push({ username, password: hashedPassword });
        res.status(201).json({ message: "User registered successfully" });
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
});

// Login endpoint
app.post('/login', async (req, res) => { 
    const { username, password } = req.body;
    // Check if the user exists
    const user = users.find(user => user.username === username);

    if (!user) {
        return res.status(401).json({ message: "Invalid username or password" });
    }

    try {
        // Compare passwords
        if (await bcrypt.compare(password, user.password)) {
            // Passwords match, generate token
            const token = jwt.sign({ username }, SECRET_KEY);
            return res.status(200).json({ token });
        } else {
            return res.status(401).json({ message: "Invalid username or password" });
        }
    } catch (error) {
        res.status(500).json({ message: "Internal Server Error" });
    }
});

// Serve the HTML file
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Protected route
app.get('/protected', authenticateToken , (req, res) => { 
    res.json({ message: "Protected route accessed successfully" });
});

// Authenticate token middleware
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) {
        return res.sendStatus(401);
    }
    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.sendStatus(403);
        }
        req.user = user;
        next();
    });
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
