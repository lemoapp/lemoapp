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


app.post('/api/set-currency', async (req, res) => {
    const { email, currency } = req.body;

    try {
        // Update the user's default currency
        await pool.query(
            'UPDATE users SET currency = ? WHERE email = ?',
            [currency, email]
        );

        res.json({ success: true, message: 'Currency set successfully! Proceed to transaction PIN creation.' });
    } catch (error) {
        console.error('Error setting currency:', error);
        res.status(500).json({ success: false, message: 'An error occurred while setting the currency. Please try again.' });
    }
});


app.post('/api/set-transaction-pin', async (req, res) => {
    const { email, transactionPin } = req.body;

    try {
        // Update the user's transaction PIN
        await pool.query(
            'UPDATE users SET transaction_password = ? WHERE email = ?',
            [transactionPin, email]
        );

        res.json({ success: true, message: 'Transaction PIN set successfully! Proceed to login.' });
    } catch (error) {
        console.error('Error setting transaction PIN:', error);
        res.status(500).json({ success: false, message: 'An error occurred while setting the transaction PIN. Please try again.' });
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

        // Include the `currency` column in the query
        const [rows] = await pool.query(
            'SELECT balance, income, expenses, total_bills, savings, currency FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            console.log('No user found');
            return res.status(404).json({ message: 'User not found' });
        }

        console.log('User data:', rows[0]);

        // Ensure the values are properly formatted
        const userData = {
            balance: parseFloat(rows[0].balance),
            income: parseFloat(rows[0].income),
            expenses: parseFloat(rows[0].expenses),
            total_bills: parseFloat(rows[0].total_bills),
            savings: parseFloat(rows[0].savings),
            currency: rows[0].currency || 'USD', // Default to USD if currency is not set
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



// Route to fetch all cards for a user
app.get('/api/cards', async (req, res) => {
    const { email } = req.query;

    console.log('Fetching cards for user:', email);

    if (!email) {
        return res.status(400).json({ success: false, message: 'Email is required' });
    }

    try {
        // Fetch cards from the database
        const [cards] = await pool.query('SELECT * FROM cards WHERE email = ?', [email]);

        if (!cards || cards.length === 0) {
            return res.status(200).json({ success: true, cards: [] }); // No cards found
        }

        console.log('Fetched cards:', cards);

        res.status(200).json({ success: true, cards });
    } catch (error) {
        console.error('Error fetching cards:', error);
        res.status(500).json({ success: false, message: 'Error fetching cards' });
    }
});



app.post('/api/cards/create', async (req, res) => {
    const { email } = req.body;

    try {
       // Step 1: Fetch user details to check their balance
const [users] = await pool.query('SELECT balance FROM users WHERE email = ?', [email]);

if (!users || users.length === 0) {
    return res.status(404).json({ message: 'User not found' });
}

const currentBalance = parseFloat(users[0].balance);

if (isNaN(currentBalance)) {
    return res.status(500).json({ message: 'Invalid balance value for the user' });
}

if (currentBalance < 10) {
    return res.status(400).json({ message: 'Insufficient balance to create a card' });
}

// Step 2: Deduct $10 from user's balance
const updatedBalance = currentBalance - 10;
await pool.query('UPDATE users SET balance = ? WHERE email = ?', [updatedBalance, email]);


        // Step 3: Generate card details
        const cardNumber = generateCardNumber(); // Function to generate a Mastercard-like number
        const cvv = generateCVV(); // Function to generate a random 3-digit CVV
        const expiryDate = generateExpiryDate(); // Function to generate expiry date 2 years from now

        // Step 4: Store the card details in the database
        await pool.query(
            'INSERT INTO cards (email, card_number, cvv, expiry_date, card_type, is_frozen) VALUES (?, ?, ?, ?, ?, ?)',
            [email, cardNumber, cvv, expiryDate, 'MasterCard', 0] // Assuming 'MasterCard' is the card type
        );

        res.status(201).json({ message: 'Card created successfully', cardNumber, cvv, expiryDate });
    } catch (error) {
        console.error('Error creating card:', error);
        res.status(500).json({ message: 'Error creating card' });
    }
});

// Helper functions
function generateCardNumber() {
    // Mastercard card numbers start with "5" and are 16 digits long
    let cardNumber = "5";
    for (let i = 0; i < 15; i++) {
        cardNumber += Math.floor(Math.random() * 10); // Add random digits
    }
    return cardNumber;
}

function generateCVV() {
    // Generate a random 3-digit CVV
    return Math.floor(100 + Math.random() * 900).toString();
}

function generateExpiryDate() {
    // Set expiry date to 2 years from now
    const now = new Date();
    const expiryYear = now.getFullYear() + 2;
    const expiryMonth = String(now.getMonth() + 1).padStart(2, '0'); // Ensure 2 digits
    return `${expiryMonth}/${expiryYear}`;
}



// Freeze/Unfreeze Card Route
app.post('/api/cards/freeze', async (req, res) => {
    const { cardNumber } = req.body;

    try {
        // Step 1: Fetch the card details based on cardNumber
        const [card] = await pool.query('SELECT * FROM cards WHERE card_number = ?', [cardNumber]);

        if (!card) {
            return res.status(404).json({ message: 'Card not found' });
        }

        // Step 2: Toggle the freeze status (1 = frozen, 0 = active)
        const newFreezeStatus = card.is_frozen === 1 ? 0 : 1;

        await pool.query('UPDATE cards SET is_frozen = ? WHERE card_number = ?', [newFreezeStatus, cardNumber]);

        const message = newFreezeStatus === 1 ? 'Card frozen successfully' : 'Card unfreezed successfully';
        res.status(200).json({ message });
    } catch (error) {
        console.error('Error freezing/unfreezing card:', error);
        res.status(500).json({ message: 'Error freezing/unfreezing card' });
    }
});



app.delete('/api/cards/delete', async (req, res) => {
    const { cardNumber, transactionPassword } = req.body;

    try {
        // Fetch the card details based on cardNumber
        const [card] = await pool.query('SELECT * FROM cards WHERE card_number = ?', [cardNumber]);

        if (!card) {
            return res.status(404).json({ message: 'Card not found' });
        }

        // Assuming 'card.email' is the user's email (passed in the request)
const [user] = await pool.query('SELECT transaction_password FROM users WHERE email = ?', [card.email]);

console.log("User data:", user); // Log the user object to check if it contains the transaction_password field

if (user && user.transaction_password) {
    console.log("Stored Password (from DB):", user.transaction_password);
} else {
    console.log("Transaction password not found or is null");
}

        // Ensure the entered transaction password is a string (since input is a string)
        const enteredPassword = transactionPassword.trim(); // Trim any leading/trailing spaces

        // Log the entered and stored passwords for debugging
        console.log("Entered Password (trimmed):", enteredPassword);
        console.log("Stored Password (from DB):", user.transaction_password);

        // Convert the stored transaction password to a string and compare
        const storedPassword = String(user.transaction_password).trim();

        // Compare the entered password (string) with the stored password (also a string)
        if (enteredPassword !== storedPassword) {
            return res.status(400).json({ message: 'Incorrect transaction password' });
        }

        // Delete the card from the database
        await pool.query('DELETE FROM cards WHERE card_number = ?', [cardNumber]);

        res.status(200).json({ message: 'Card deleted successfully' });
    } catch (error) {
        console.error('Error deleting card:', error);
        res.status(500).json({ message: 'Error deleting card' });
    }
});

app.post('/api/update-username', async (req, res) => {
    const { email, newUsername } = req.body;

    try {
        await pool.query('UPDATE users SET fullName = ? WHERE email = ?', [newUsername, email]);
        res.json({ success: true, message: 'Username updated successfully' });
    } catch (error) {
        console.error('Error updating username:', error);
        res.status(500).json({ success: false, message: 'Failed to update username' });
    }
});


app.post('/api/update-address', async (req, res) => {
    const { email, newAddress } = req.body;

    try {
        await pool.query('UPDATE users SET address = ? WHERE email = ?', [newAddress, email]);
        res.json({ success: true, message: 'Address updated successfully' });
    } catch (error) {
        console.error('Error updating address:', error);
        res.status(500).json({ success: false, message: 'Failed to update address' });
    }
});


app.post('/api/update-password', async (req, res) => {
    const { email, oldPassword, newPassword } = req.body;

    try {
        const [rows] = await pool.query('SELECT password FROM users WHERE email = ?', [email]);
        if (rows.length === 0 || rows[0].password !== oldPassword) {
            return res.status(400).json({ success: false, message: 'Incorrect old password' });
        }

        await pool.query('UPDATE users SET password = ? WHERE email = ?', [newPassword, email]);
        res.json({ success: true, message: 'Password updated successfully' });
    } catch (error) {
        console.error('Error updating password:', error);
        res.status(500).json({ success: false, message: 'Failed to update password' });
    }
});


app.post('/api/forgot-password', async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ message: 'Email is required.' });
    }

    try {
        // Check if the email exists in the database
        const [rows] = await pool.query('SELECT password FROM users WHERE email = ?', [email]);
        if (rows.length === 0) {
            return res.status(404).json({ message: 'Email not found.' });
        }

        const plainTextPassword = rows[0].password;

        // Send the password via email
        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASS
            }
        });

        await transporter.sendMail({
            from: 'no-reply@vanguardroyalbank.com',
            to: email,
            subject: 'Your Vanguard Royal Bank Password',
            html: `<p>Your password is: <strong>${plainTextPassword}</strong></p>
                   <p>Use it to log in to your account <a href="https://lemoapp.onrender.com/index.html">here</a>.</p>`
        });

        res.status(200).json({ message: 'Password sent to your email.' });
    } catch (error) {
        console.error('Error retrieving password:', error);
        res.status(500).json({ message: 'An error occurred while retrieving your password.' });
    }
});


async function authenticateUser(req, res, next) {
    const { email } = req.body;

    if (!email) {
        return res.status(400).send({ error: 'Email is required' });
    }

    try {
        // Use pool to query the database
        const [results] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);

        if (results.length === 0) {
            return res.status(401).send({ error: 'Unauthorized: User not found' });
        }

        // Attach user ID to the request object
        req.userId = results[0].id;
        next();
    } catch (err) {
        console.error('Database error:', err);
        res.status(500).send({ error: 'Internal Server Error' });
    }
}



app.post('/api/claim-status', authenticateUser, async (req, res) => {
    const email = req.body.email;
    
    try {
        // Get user ID based on email
        const [userResults] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
        if (userResults.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        const userId = userResults[0].user_id;

        // Fetch claim data for the user
        const [claimData] = await pool.query('SELECT claim_date, total_claims FROM claims WHERE user_id = ?', [userId]);

        if (claimData.length > 0) {
            const claim = claimData[0];
            const claimedToday = new Date(claim.claim_date).toDateString() === new Date().toDateString();
            res.json({
                totalClaims: claim.total_claims,
                claimedToday,
            });
        } else {
            // No claim data found
            res.json({
                totalClaims: 0,
                claimedToday: false,
            });
        }
    } catch (err) {
        console.error('Error fetching claim status:', err);
        res.status(500).json({ error: 'Error fetching claim data' });
    }
});



app.post('/api/claim', authenticateUser, async (req, res) => {
    const userId = req.userId;

    try {
        // Retrieve the latest claim data for the user
        const [results] = await pool.query(
            'SELECT claim_date, total_claims FROM claims WHERE user_id = ?',
            [userId]
        );

        const claimData = results[0];
        const claimedToday = claimData && new Date(claimData.claim_date).toDateString() === new Date().toDateString();

        if (claimedToday) {
            return res.status(400).send({ message: 'Already claimed today!' });
        }

        const totalClaims = (claimData ? claimData.total_claims : 0) + 1;

        // Insert or update the claim data
        await pool.query(
            `INSERT INTO claims (user_id, claim_date, total_claims)
             VALUES (?, CURDATE(), ?)
             ON DUPLICATE KEY UPDATE claim_date = CURDATE(), total_claims = ?`,
            [userId, totalClaims, totalClaims]
        );

        res.send({ success: true, totalClaims });
    } catch (err) {
        console.error('Error handling claim:', err);
        res.status(500).send({ error: 'Database error' });
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
