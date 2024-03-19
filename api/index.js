const express = require('express');
const cors = require('cors');
const app = express();
const mongoose = require('mongoose');

const User = require('./models/User');
const Post = require('./models/Post');

const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const cookieParser = require('cookie-parser');
const multer = require('multer');
const uploadMiddleware = multer({ dest: 'uploads/' });
const fs = require('fs');

app.use(cors({ credentials: true, origin: 'http://localhost:3000' }));
app.use(express.json());
app.use(cookieParser());
app.use('/uploads',express.static(__dirname+'/uploads'));

const secret = 'ascbsdcsvdcwv23f62f2c2g2332fc2vtbynpj';

mongoose.connect('mongodb://127.0.0.1:27017/userDb');

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    try {
        const salt = bcrypt.genSaltSync(10);
        const hashedPassword = bcrypt.hashSync(password, salt);
        const user = new User({ username, password: hashedPassword });
        await user.save();
        res.json({ message: "User registered successfully" });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const userCreds = await User.findOne({ username });
        if (!userCreds) {
            return res.status(404).json({ error: "User not found" });
        }
        const userPass = bcrypt.compareSync(password, userCreds.password);
        if (userPass) {
            jwt.sign({ username, id: userCreds._id }, secret, {}, (err, token) => {
                if (err) throw err;
                res.cookie('token', token, { httpOnly: true }).json({
                    id: userCreds._id,
                    username,
                });
            });
        } else {
            res.status(401).json({ error: "Incorrect password" });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: "Internal server error" });
    }
});

app.get('/profile', (req, res) => {
    const { token } = req.cookies;
    if (!token) {
        return res.status(401).json({ error: "Unauthorized" });
    }
    jwt.verify(token, secret, (err, authData) => {
        if (err) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        res.json(authData);
    });
});

app.post('/logout', (req, res) => {
    res.cookie('token', '').json('token invalidated!');
});

app.post('/post', uploadMiddleware.single('file'), async (req, res) => {
    const { originalname, path } = req.file;
    const parts = originalname.split('.');
    const ext = parts[parts.length - 1];
    const newPath = path + '.' + ext;
    fs.renameSync(path, newPath);

    const { token } = req.cookies;
    jwt.verify(token, secret, async (err, authData) => {
        if (err) {
            return res.status(401).json({ error: "Unauthorized" });
        }
        try {
            const { title, summary, content } = req.body;
            const post = new Post({ title, summary, content, cover: newPath, author: authData.id });
            await post.save();
            res.json({post});
        } catch (error) {
            console.error(error);
            res.status(500).json({ error: "Post creation error!" });
        }
    });
});

app.get('/post', async (req, res) => {
    const posts = await Post.find().populate('author',['username']).sort({createdAt:-1}).limit(20);
    res.json(posts);
});

app.get('/post/:id', async (req, res) => {
    const {id} = req.params;
    Post.findById(id).then((post)=>{
        if(!post){return res.status(404).json({msg:"No post found"})}
        res.json(post);
    }).catch((err)=>res.status(500).json(err));
});

app.listen(4000, () => {
    console.log("connected to port 4000!");
});
