const express = require('express');
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const Routes = require('./routes/route');
const ConnectDB = require('./config/db');
const authRoutes = require('./auth/routes/authRoutes');
const authenticateToken = require('./auth/middlewares/authMiddleware');
const morgan = require('morgan');
const cors = require("cors");
const app = express();

dotenv.config();
ConnectDB();

// Middlewares
app.use(cors());
app.use(express.json());
app.use(morgan("dev"));
app.use('/protected', authenticateToken);
app.use('/protected', Routes);
app.use('/auth', authRoutes);
app.use('/', Routes);


const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log("Successfully Connected with PORT: ", PORT);
});