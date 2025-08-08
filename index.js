import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = 3000;
const db = new pg.Pool({
    password: 'Pk@337382',
    user: 'postgres',
    host: 'localhost', 
    database: 'event_management',
    port: 5432,
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
express.static('public');
app.use(cors());

