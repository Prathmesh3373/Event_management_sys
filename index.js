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

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'] ;
    console.log(authHeader);
    const token = authHeader.split(' ')[1]; 
    if (!token) return res.sendStatus(401);
    jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
express.static('public');
app.use(cors());
// authentication functions
app.post('/api/register', async (req, res) => {
    const { username, password, isadmin } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    try {
        const result = await db.query('INSERT INTO users (username, password,isadmin) VALUES ($1, $2) RETURNING id', [username, hashedPassword,isadmin]);
        res.status(201).json({ userId: result.rows[0].id });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
}
);

app.post('/api/login',async (req, res) => {
    const {username,password,isadmin} = req.body;
    try{
        const result = await db.query('select * from users where username  = $1',[username]);
        if(result.rows.length > 0){
            const user = result.rows[0];            
            const isMatch = await bcrypt.compare(password, user.password);
            if(isMatch){
                const token = jwt.sign({userId: user.id, isadmin: user.isadmin}, process.env.JWT_SECRET, {expiresIn: '1h'});
                res.status(200).json({token});
            } else {
                res.status(401).json({error: 'Invalid credentials'});
            }
        } else {
            res.status(404).json({error: 'User not found'});
        }
    }
    catch(error){
        res.status(500).json({error: 'Database error'});
    }
});

// user functions 

//showing the user all events 
app.get('/api/all-events', async (req, res) => {
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
app.get('api/events/filter', async (req, res) => {
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
app.delete('/api/cancel-registration', async (req, res) => {
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
app.post('/api/register-event', authenticateToken, async (req, res) => {
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
app.get('/api/user-registrations', authenticateToken, async (req, res) =>{
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
app.post('/api/create-event', authenticateToken, async (req, res) => {
    if (!req.user.isadmin) {
        return res.status(403).json({ error: 'Access denied' });
    }
    const { name, date, location,type } = req.body;
    try {
        const result = await db.query('INSERT INTO events (name, date, location, description) VALUES ($1, $2, $3, $4, $5) RETURNING *', [name, date, location, description]);
        res.status(201).json({ event: result.rows[0] });
    } catch (error) {
        res.status(500).json({ error: 'Database error' });
    }
});
// for the admin to update an event
app.put('/api/update-event/:id', authenticateToken, async (req, res) => {
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
app.delete('/api/delete-event/:id', authenticateToken, async (req, res) =>{
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
app.get('/api/admin/registrations', authenticateToken, async (req, res) => {
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


