import express from 'express';
import bodyParser from 'body-parser';
import pg from 'pg';
import cors from 'cors';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import ejs from 'ejs';





const app = express();
const PORT = 3000;
dotenv.config();

 
app.set('view engine', 'ejs');
const db = new pg.Pool({
    password: process.env.my_PASSWORD,
    user: process.env.my_USER,
    host: process.env.my_HOST, 
    database: process.env.my_DATABASE,
    port: process.env.my_PORT,
});
// db.connect();

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] ;
    // console.log(authHeader); 
    const token = authHeader.split(' ')[1]; 
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

const isadmin = (req , res , next) =>{
    if(!req.user.isadmin){
        return res.status(403).json({ error: 'Access denied' });
    }
    next();
};

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cors());
// authentication functions
app.post('/register', async (req, res) => {
    const { username, password, is_admin = false } = req.body;
    try {
        // Hash the password for security
        const hashedPassword = await bcrypt.hash(password, 10);
        // Insert user with corrected column names
        const result = await db.query(
            'INSERT INTO users (username, password_hash, is_admin) VALUES ($1, $2, $3) RETURNING id',
            [username, hashedPassword, is_admin]
        );
        res.status(201).json({ userId: result.rows[0].id, message: 'User registered successfully' });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Username already exists or a database error occurred.' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await db.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length > 0) {
            const user = result.rows[0];
            // Compare the provided password with the hashed password from the correct column
            const isMatch = await bcrypt.compare(password, user.password_hash);
            if (isMatch) {
                // Generate a JWT with the correct user data
                const token = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, process.env.JWT_SECRET, { expiresIn: '1h' });
                res.status(200).json({ token });
            } else {
                res.status(401).json({ error: 'Invalid credentials' });
            }
        } else {
            res.status(404).json({ error: 'User not found' });
        }
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});

// user functions 

//showing the user all events 
app.get('/all-events', async (req, res) => {
    try {
        const result = await db.query('SELECT * FROM events');
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No events found' });
        }
        res.status(200).json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

// for users who are selecting filter option for location and date
app.get('/events/filter',authenticateToken ,async (req, res) => {
    const {location, date, typeof_event} = req.query;
    try{
        if(location && !date && !typeof_event) {
            const result = await db.query('select * from events where location = $1',[location]);
            if(result.rows.length === 0) {
        const result = await db.query('select * from events where location =$1 and date = $2',[location,date]);
            }
        }
        if(date && !location && !typeof_event) {
            const result = await db.query('select * from events where date = $1',[date]);
            if(result.rows.length === 0) {
                return res.status(404).json({error: 'No events found for the given filter'});
            }
        }
        if(!date && !location && typeof_event) {
            const result = await db.query('select * from events where type = $1',[typeof_event]);
            if(result.rows.length === 0) {
                return res.status(404).json({error: 'No events found for the given filter'});
            }
        }
        console.log(result.rows);
        let event_date = new Date(result.rows[0].date);
        let current_date = new Date();
        if(event_date < current_date) {
            return res.status(400).json({error: 'Event date cannot be in the past'});
        }
        if(result.rows.length === 0) {
            return res.status(404).json({error: 'No events found for the given filter'});
        }
        res.status(200).json(result.rows);
    }
    catch(error){
        res.status(500).json({error: 'Database error'});
    }
});

//cancel event registration
app.delete('/cancel-registration',authenticateToken, async (req, res) => {
    const { eventId } = req.query;
    const userId = req.user.id; // Assuming user ID is available in the request
    try {
        const result = await db.query('DELETE FROM registrations WHERE event_id = $1 AND user_id = $2 RETURNING *', [eventId, userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Registration not found' });
        }
        res.status(200).json({ message: 'Registration cancelled successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

//register for an event
app.post('/register-event', authenticateToken, async (req, res) => {
    const { eventId } = req.body;
    const userId = req.user.userId; // Assuming user ID is available in the request
    try {
        const result = await db.query('INSERT INTO registrations (event_id, user_id) VALUES ($1, $2) RETURNING *', [eventId, userId]);
        res.status(201).json({ registration: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

//get all registrations for a user
app.get('/user-registrations', authenticateToken, async (req, res) =>{
    const userId = req.user.userId; // Assuming user ID is available in the request
    try {
        const result = await db.query('SELECT * FROM registrations WHERE user_id = $1', [userId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No registrations found for this user' });
        }
        res.status(200).json(result.rows);
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }

});

// for the admin to create an event
app.post('/create-event', authenticateToken, isadmin, async (req, res) => {
    const { name, date, location, description, time, capacity } = req.body;
    try {
        // Corrected query with all parameters
        const result = await db.query(
            'INSERT INTO events (name, date, location, description, time, capacity) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
            [name, date, location, description, time, capacity]
        );
        res.status(201).json({ event: result.rows[0], message: 'Event created successfully' });
    } catch (error) {
        console.error('Create event error:', error);
        res.status(500).json({ error: 'Database error' });
    }
});
// for the admin to update an event
app.put('/update-event/:id', authenticateToken, isadmin, async (req, res) => {
    if (!req.user.isadmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    const eventId = req.params.id;
    const { name, date, location, description } = req.body;
    try {
        const result = await db.query('UPDATE events SET name = $1, date = $2, location = $3, description = $4 WHERE id = $5 RETURNING *', [name, date, location, description, eventId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }
        res.status(200).json({ event: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});

// for the admin to delete an event
app.delete('/delete-event/:id', authenticateToken,isadmin, async (req, res) =>{
    const eventId = req.params.id;
    if (!req.user.isadmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    try {
        const result = await db.query('DELETE FROM events WHERE id = $1 RETURNING *', [eventId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Event not found' });
        }
        res.status(200).json({ message: 'Event deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
} );

// for the admin to view all registrations
app.get('/admin/registrations', authenticateToken,isadmin, async (req, res) => {
    if(!req.user.isadmin){
        return res.status(403).json({ error: 'Access denied' });
    }
    try{
        const result = await db.query('SELECT * FROM registrations');
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No registrations found' });
        }
        res.status(200).json(result.rows);
    }
    catch(error){
        res.status(500).json({ error: 'Database error' });
     
    }
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});


