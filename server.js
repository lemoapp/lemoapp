// Import required modules
const express = require('express');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise'); // For MySQL database
const cors = require('cors');
const path = require('path');
const axios = require('axios');

// Load environment variables
dotenv.config();


// Initialize Express app
const app = express();

// Middleware
// Enable CORS for cross-origin requests
app.use(cors({
    origin: '*', // Or specify the domains allowed to access
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json()); // Parse incoming JSON requests
app.use(express.static(path.join(__dirname))); // Serve static files
app.use(express.urlencoded({ extended: true })); // Parse URL-encoded data

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    connectionLimit: 10
});

// Sample route for testing database connection
app.get('/test-db', async (req, res) => {
    try {
        const [rows] = await db.query('SELECT 1 + 1 AS solution');
        res.json({ success: true, message: `Database is connected: ${rows[0].solution}` });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Database connection failed', details: err.message });
    }
});

async function sendEmail(to, subject, htmlContent) {
    try {
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER, 
                pass: process.env.EMAIL_PASS 
            }
        });

        // Set up email options
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: to,
            subject: subject, 
            html: htmlContent
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully');
    } catch (error) {
        console.error('Error sending email:', error);
        throw error; // Ensure errors are propagated for proper handling
    }
}

app.post('/api/signup', async (req, res) => {
    const { fullName, email, password } = req.body;

    try {
        // Check if user already exists
        const [existingUser] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        if (existingUser.length > 0) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        // Insert user into the database
        await pool.query(
            'INSERT INTO users (fullName, email, password, verified) VALUES (?, ?, ?, ?)', 
            [fullName, email, password, false]
        );

        // Generate OTP
        const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP

        // Store the OTP in the database
        await pool.query('UPDATE users SET otp = ? WHERE email = ?', [otp, email]);

        // Send OTP to the user via email
        const subject = 'Your OTP Code for Lemo';
        const htmlContent = `<p>Hello ${fullName},</p>
                             <p>Your OTP code is <strong>${otp}</strong>. Please use it to verify your account.</p>`;
        await sendEmail(email, subject, htmlContent);

        res.json({ message: 'Signup successful! Check your email for the OTP.' });
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).json({ message: 'Signup failed. Please try again.' });
    }
});



app.post('/api/verify-otp', async (req, res) => {
    const { email, otp } = req.body;

    try {
        // Check if the email and OTP match in the database
        const [rows] = await pool.query(
            'SELECT * FROM users WHERE email = ? AND otp = ? AND otp_used = 0',
            [email, otp]
        );

        if (rows.length === 0) {
            return res.status(400).json({ success: false, message: 'Invalid OTP or OTP already used.' });
        }

        // Mark the OTP as used
        await pool.query(
            'UPDATE users SET otp_used = 1 WHERE email = ?',
            [email]
        );

        // Mark the user as verified
        await pool.query(
            'UPDATE users SET verified = 1 WHERE email = ?',
            [email]
        );

        // Send success response
        res.json({ success: true, message: 'OTP verified successfully! You can now log in.' });
    } catch (error) {
        console.error('OTP verification error:', error);
        res.status(500).json({ success: false, message: 'An error occurred during OTP verification. Please try again.' });
    }
});

app.post('/api/login', async (req, res) => { 
    console.log("Login request received");
    const { email, password } = req.body;

    if (!email || !password) {
        console.log("Missing email or password");
        return res.status(400).json({ message: 'Please provide both email and password.' });
    }

    console.log("Checking user in database...");

    try {
        // Query the database for the user with the provided email
        const [results] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        console.log('Query Results:', results); // Log the result of the query

        if (results.length === 0) {
            console.log("User not found");
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        const user = results[0];
        console.log('User found:', user);

        // Direct password comparison (no hashing, just plain text match)
        if (password !== user.password) {
            console.log("Password does not match");
            return res.status(401).json({ message: 'Invalid email or password.' });
        }

        console.log("Login successful");
        return res.status(200).json({ message: 'Login successful!' });
    } catch (err) {
        console.error("Database error:", err);
        return res.status(500).json({ message: 'Database error' });
    }
});






// Example route for sending an email using Nodemailer
app.post('/send-email', async (req, res) => {
    const { to, subject, text } = req.body;

    try {
        // Configure nodemailer transporter
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS,
            },
        });

        // Send email
        await transporter.sendMail({
            from: process.env.EMAIL_USER,
            to,
            subject,
            text,
        });

        res.json({ success: true, message: 'Email sent successfully' });
    } catch (err) {
        res.status(500).json({ success: false, error: 'Failed to send email', details: err.message });
    }
});




app.get('/api/dashboard', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    try {
        console.log('Fetching user data for email:', email);
        const [rows] = await pool.query('SELECT balance, income, expenses, total_bills, savings FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            console.log('No user found');
            return res.status(404).json({ message: 'User not found' });
        }

        console.log('User data:', rows[0]);

        // Ensure the values are numbers
        const userData = {
            balance: parseFloat(rows[0].balance),
            income: parseFloat(rows[0].income),
            expenses: parseFloat(rows[0].expenses),
            total_bills: parseFloat(rows[0].total_bills),
            savings: parseFloat(rows[0].savings),
        };

        res.status(200).json({ message: 'User data fetched successfully', data: userData });
    } catch (error) {
        console.error('Database query error:', error);
        res.status(500).json({ message: 'Database error' });
    }
});



app.get('/api/transactions', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    try {
        console.log('Fetching transactions for email:', email);
        // Replace 'date' with the correct column name, e.g., 'created_at'
        const [transactions] = await pool.query('SELECT * FROM transactions WHERE email = ? ORDER BY date DESC LIMIT 2', [email]);

        if (transactions.length === 0) {
            return res.status(200).json({ message: 'No transactions found', data: [] }); // No transactions for the user
        }

        res.status(200).json({ message: 'Transactions fetched successfully', data: transactions });
    } catch (error) {
        console.error('Database error:', error);
        res.status(500).json({ message: 'Database error' });
    }
});



app.get('/api/user-balance', async (req, res) => {
    const { email } = req.query;

    try {
        const [rows] = await pool.query('SELECT balance FROM users WHERE email = ?', [email]);

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        res.json({ success: true, balance: rows[0].balance });
    } catch (error) {
        console.error('Error fetching user balance:', error);
        res.status(500).json({ success: false, message: 'Error fetching balance' });
    }
});




app.post('/api/send-funds', async (req, res) => {
    const { email, amount, recipient, transferType, bankName, accountNumber, routingNumber } = req.body;

    try {
        // Get user's current balance
        const [user] = await pool.query('SELECT balance FROM users WHERE email = ?', [email]);

        if (user.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const currentBalance = user[0].balance;

        // Check if sufficient balance
        if (currentBalance < amount) {
            return res.status(400).json({ success: false, message: 'Insufficient funds' });
        }

        // Log the transfer in the 'transfers' table first (status: pending)
        const transferDetails = {
            email,
            amount,
            recipient,
            transferType,
            bankName: bankName || null,
            accountNumber: accountNumber || null,
            routingNumber: routingNumber || null,
            status: 'pending'
        };

        const [transferResult] = await pool.query('INSERT INTO transfers SET ?', transferDetails);
        
        // Check if the insert was successful
        if (!transferResult.insertId) {
            return res.status(500).json({ success: false, message: 'Error logging transfer' });
        }

        // Deduct amount from user's balance
        await pool.query('UPDATE users SET balance = balance - ? WHERE email = ?', [amount, email]);

        // Log the transaction in the 'transactions' table
        const transactionDetails = {
            email,
            amount,
            recipient,
            transferType,
            bankName: bankName || null,
            accountNumber: accountNumber || null,
            routingNumber: routingNumber || null,
            date: new Date()
        };

        await pool.query('INSERT INTO transactions SET ?', transactionDetails);

        // Update transfer status to 'completed'
        await pool.query('UPDATE transfers SET status = ? WHERE id = ?', ['completed', transferResult.insertId]);

        res.json({ success: true, message: 'Transaction successful' });
    } catch (error) {
        console.error('Error processing transaction:', error);
        res.status(500).json({ success: false, message: 'Error processing transaction' });
    }
});



// Route to fetch user details for receiving money page
app.get('/api/user-details', async (req, res) => {
    const email = req.query.email; // Get the email from the query string

    if (!email) {
        return res.status(400).json({ message: 'Email is required' });
    }

    try {
        const [user] = await pool.query('SELECT fullName FROM users WHERE email = ?', [email]);

        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            accountName: user[0].fullName,
            accountNumber: '1234567890', // Static Account Number
            achRoutingNumber: '9876543210', // Static ACH Routing Number
            accountType: 'Checking' // Static Account Type
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ message: 'Error fetching user details' });
    }
});




app.post('/api/deposit-crypto', async (req, res) => {
    const { email, amount, cryptoType } = req.body;

    if (!email || !amount || !cryptoType) {
        return res.status(400).json({ success: false, message: 'All fields are required.' });
    }

    try {
        // Insert into the `crypto_deposits` table
        const cryptoDepositQuery = `
            INSERT INTO crypto_deposits (email, crypto_type, amount, status)
            VALUES (?, ?, ?, ?)
        `;

        await pool.query(cryptoDepositQuery, [email, cryptoType, amount, 'pending']);

        // Prepare transaction details
        const transactionQuery = `
            INSERT INTO transactions (email, type, amount, recipient, transferType, bankName, accountNumber, routingNumber, date)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        `;

        const transactionValues = [
            email,
            'crypto deposit', // type
            amount,
            null, // recipient
            'crypto deposit', // transferType
            null, // bankName
            null, // accountNumber
            null, // routingNumber
            new Date(), // current date
        ];

        await pool.query(transactionQuery, transactionValues);

        res.json({ success: true, message: 'Deposit successfully logged and set to pending.' });
    } catch (error) {
        console.error('Error logging crypto deposit:', error);
        res.status(500).json({ success: false, message: 'An error occurred while logging the deposit.' });
    }
});


app.get('/api/transactions/view', async (req, res) => {
    const email = req.query.email;

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }

    try {
        const [transactions] = await pool.query(
            'SELECT type, amount, transferType, date FROM transactions WHERE email = ? ORDER BY date DESC',
            [email]
        );

        if (transactions.length === 0) {
            return res.json({ success: true, transactions: [] });
        }

        res.json({ success: true, transactions });
    } catch (error) {
        console.error('Error fetching transactions:', error);
        res.status(500).json({ success: false, message: 'An error occurred while fetching transactions' });
    }
});



// Admin stats endpoint
app.get('/api/admin/stats', async (req, res) => {
    try {
        // Queries for each stat
        const [[{ pendingDeposits }]] = await pool.query(`
            SELECT SUM(amount) AS pendingDeposits 
            FROM crypto_deposits 
            
        `);

        // Update the withdrawals stat to count all records from `transfers` table
        const [[{ totalWithdrawals }]] = await pool.query(`
            SELECT COUNT(*) AS totalWithdrawals 
            FROM transfers
        `);

        const [[{ totalUsers }]] = await pool.query(`
            SELECT COUNT(*) AS totalUsers 
            FROM users
        `);

        const [[{ totalTransactions }]] = await pool.query(`
            SELECT COUNT(*) AS totalTransactions 
            FROM transactions
        `);

        // Respond with the updated stats
        res.json({
            pendingDeposits: pendingDeposits || 0,
            totalWithdrawals: totalWithdrawals || 0, // Updated field
            totalUsers: totalUsers || 0,
            totalTransactions: totalTransactions || 0,
        });
    } catch (error) {
        console.error('Error fetching admin stats:', error);
        res.status(500).json({ message: 'Error fetching admin stats' });
    }
});


app.get('/api/admin/details', async (req, res) => {
    const { type } = req.query;

    try {
        let results;
        switch (type) {
            case 'pendingDeposits':
                [results] = await pool.query(`
                    SELECT * FROM crypto_deposits WHERE status = 'pending'
                `);
                break;

            case 'totalWithdrawals':
                [results] = await pool.query(`
                    SELECT * FROM transfers
                `);
                break;

            case 'totalUsers':
                [results] = await pool.query(`
                    SELECT * FROM users
                `);
                break;

            case 'totalTransactions':
                [results] = await pool.query(`
                    SELECT * FROM transactions
                `);
                break;

            case 'activeUsers':
                [results] = await pool.query(`
                    SELECT * FROM users WHERE last_login >= NOW() - INTERVAL 30 DAY
                `);
                break;

            default:
                return res.status(400).json({ message: 'Invalid type' });
        }

        res.json(results);
    } catch (error) {
        console.error('Error fetching admin details:', error);
        res.status(500).json({ message: 'Error fetching details' });
    }
});


// Fetch all users
app.get('/api/admin/users', async (req, res) => {
    try {
        const [users] = await pool.query(`
            SELECT fullName, email, balance, 
                   IF(verified = true, 'Active', 'Inactive') AS status 
            FROM users
        `);
        res.json(users);
    } catch (error) {
        console.error('Error fetching users:', error);
        res.status(500).json({ message: 'Error fetching users' });
    }
});

// Delete user
app.post('/api/admin/delete-user', async (req, res) => {
    const { email } = req.body;

    try {
        // Check if user exists
        const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Delete user
        await pool.query('DELETE FROM users WHERE email = ?', [email]);
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error);
        res.status(500).json({ message: 'Error deleting user' });
    }
});

// Add funds to user
app.post('/api/admin/add-funds', async (req, res) => {
    const { email, amount } = req.body;

    try {
        // Validate amount
        if (amount <= 0) {
            return res.status(400).json({ message: 'Amount must be greater than zero' });
        }

        // Update balance
        await pool.query('UPDATE users SET balance = balance + ? WHERE email = ?', [amount, email]);
        res.json({ message: 'Funds added successfully' });
    } catch (error) {
        console.error('Error adding funds:', error);
        res.status(500).json({ message: 'Error adding funds' });
    }
});

// Remove funds from user
app.post('/api/admin/remove-funds', async (req, res) => {
    const { email, amount } = req.body;

    try {
        // Validate amount
        if (amount <= 0) {
            return res.status(400).json({ message: 'Amount must be greater than zero' });
        }

        // Check current balance
        const [[user]] = await pool.query('SELECT balance FROM users WHERE email = ?', [email]);
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        if (user.balance < amount) {
            return res.status(400).json({ message: 'Insufficient balance' });
        }

        // Update balance
        await pool.query('UPDATE users SET balance = balance - ? WHERE email = ?', [amount, email]);
        res.json({ message: 'Funds removed successfully' });
    } catch (error) {
        console.error('Error removing funds:', error);
        res.status(500).json({ message: 'Error removing funds' });
    }
});


// Route to edit user details
app.post('/api/admin/edit-user', async (req, res) => {
    const { email, fullName, balance } = req.body;

    // Validate input
    if (!email || !fullName || isNaN(balance)) {
        return res.status(400).json({ message: 'Invalid input. Please provide valid email, full name, and balance.' });
    }

    try {
        // Check if user exists
        const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
        if (user.length === 0) {
            return res.status(404).json({ message: 'User not found.' });
        }

        // Update user details
        await pool.query(
            'UPDATE users SET fullName = ?, balance = ? WHERE email = ?',
            [fullName, balance, email]
        );

        res.status(200).json({ message: 'User details updated successfully.' });
    } catch (error) {
        console.error('Error editing user details:', error);
        res.status(500).json({ message: 'An error occurred while editing user details.' });
    }
});


// Hardcoded conversion rates
const conversionRates = {
    USD: {
        EUR: 0.85,  // Example rate: 1 USD = 0.85 EUR
        GBP: 0.75,  // Example rate: 1 USD = 0.75 GBP
    },
    EUR: {
        USD: 1.18,  // Example rate: 1 EUR = 1.18 USD
    }
};


// Function to get exchange rate
function getExchangeRate(fromCurrency, toCurrency) {
    return conversionRates[fromCurrency] && conversionRates[fromCurrency][toCurrency];
}


app.post('/api/admin/convert-currency', async (req, res) => {
    const { email, targetCurrency, amount } = req.body;

    console.log('Received data:', { email, targetCurrency, amount });

    // Check if required fields are provided
    if (!email || !targetCurrency || !amount) {
        return res.status(400).json({ message: 'Missing required fields' });
    }

    try {
        // Fetch user details
        const [user] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);

        console.log('Fetched user data:', user);

        if (!user || !user.currency) {
            return res.status(404).json({ message: 'User not found or currency not set' });
        }

        const currentCurrency = user.currency;

        console.log(`User currency: ${currentCurrency}, Target currency: ${targetCurrency}`);

        // If the user is trying to convert to the same currency
        if (currentCurrency === targetCurrency) {
            return res.status(400).json({ message: 'User is already in the selected currency' });
        }

        // Fetch the exchange rate from hardcoded conversion rates
        const rate = getExchangeRate(currentCurrency, targetCurrency);

        console.log(`Fetching rate from ${currentCurrency} to ${targetCurrency}: ${rate}`);

        if (!rate) {
            return res.status(400).json({ message: `Conversion rate not available for ${currentCurrency} to ${targetCurrency}` });
        }

        // Calculate converted amount
        const convertedAmount = amount * rate;

        // Apply the transaction fee (2%)
        const fee = (convertedAmount * 0.02);
        const finalAmount = convertedAmount - fee;

        // Update user’s balance and currency
        await pool.query('UPDATE users SET balance = ?, currency = ? WHERE email = ?', [finalAmount, targetCurrency, email]);

        // Log the conversion in currency_conversions table
        await pool.query('INSERT INTO currency_conversions (user_email, from_currency, to_currency, amount, converted_amount, fee, rate) VALUES (?, ?, ?, ?, ?, ?, ?)', [
            email, currentCurrency, targetCurrency, amount, finalAmount, fee, rate
        ]);

        res.status(200).json({ message: 'Currency converted successfully', convertedAmount: finalAmount, fee });

    } catch (error) {
        console.error('Error during currency conversion:', error);
        res.status(500).json({ message: 'Error during currency conversion' });
    }
});







// Catch-all route for invalid paths
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Route not found' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
