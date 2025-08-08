import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

const app = express();
const PORT = 3000;
dotenv.config();

const db = new pg.Pool({
    password: process.env.my_PASSWORD,
    user: process.env.my_USER,
    host: process.env.my_HOST, 
    database: process.env.my_DATABASE,
    port: process.env.my_PORT,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
express.static('public');
app.use(cors());

