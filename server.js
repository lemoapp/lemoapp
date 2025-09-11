// Import required modules
const express = require('express');
const nodemailer = require('nodemailer');
const dotenv = require('dotenv');
const mysql = require('mysql2/promise'); // For MySQL database
const cors = require('cors');
const path = require('path');
const axios = require('axios');
const fs = require('fs');
const PDFDocument = require('pdfkit'); // For PDF generation
const crypto = require('crypto'); // For generating hash codes


// Load environment variables
dotenv.config();


// Initialize Express app
const app = express();
app.use(express.json())

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
        // Configure the transporter with Zoho Mail's SMTP details
        const transporter = nodemailer.createTransport({
            host: 'smtp.zoho.com', // SMTP server for Zoho
            port: 465,            // Port for SSL
            secure: true,         // Use SSL
            auth: {
                user: process.env.EMAIL_USER, // Your professional Zoho email address
                pass: process.env.EMAIL_PASS  // Your Zoho email password or App-specific password
            }
        });

        // Set up email options
        const mailOptions = {
            from: process.env.EMAIL_USER, // Sender's email
            to: to,                       // Recipient's email
            subject: subject,             // Email subject
            html: htmlContent             // HTML content of the email
        };

        // Send the email
        await transporter.sendMail(mailOptions);
        console.log('Email sent successfully via Zoho Mail');
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

    // Predefined values for each currency
    const currencyDetails = {
        USD: {
            account_number: "8398170700",
            ach_routing_number: "026073150",
            iban: null, // Not applicable for USD
            swift_code: null, // Not applicable for USD
            sort_code: null, // Not applicable for USD
        },
        EUR: {
            account_number: "66908937",
            ach_routing_number: null, // Not applicable for EUR
            iban: "GB71CLJU04130766908937", // Not provided
            swift_code: "CLJUGB21XXX",
            sort_code: null,
        },
        GBP: {
            account_number: "66908937",
            ach_routing_number: null, // Not applicable for GBP
            iban: null,
            swift_code: "CLJUGB21XXX",
            sort_code: "041307", // Not provided
        }
    };

    // Get the details for the selected currency
    const details = currencyDetails[currency];

    if (!details) {
        return res.status(400).json({ success: false, message: 'Invalid currency selected.' });
    }

    try {
        // Update the user's details in the database
        const query = `
            UPDATE users 
            SET currency = ?, 
                account_number = ?, 
                ach_routing_number = ?, 
                iban = ?, 
                swift_code = ?, 
                sort_code = ? 
            WHERE email = ?
        `;

        await pool.query(query, [
            currency,
            details.account_number,
            details.ach_routing_number,
            details.iban,
            details.swift_code,
            details.sort_code,
            email,
        ]);

        res.json({ success: true, message: 'Currency and account details set successfully!' });
    } catch (error) {
        console.error('Error setting currency and account details:', error);
        res.status(500).json({ success: false, message: 'An error occurred while setting the currency and account details.' });
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



const LANGUAGE_DIR = path.join(__dirname, 'blackrocklanguages');

// Function to load translations (Specific to BlackRock Receipts)
function loadBlackrockTranslations(language) {
    const filePath = path.join(LANGUAGE_DIR, `${language}.json`);
    if (fs.existsSync(filePath)) {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
    return null;
}



app.post('/generate-receipts', (req, res) => {
    const { month, year, day, date, paymentTo, currency, transaction1, transaction2, bankName, language } = req.body;

    // Hardcode the category
    const category = "profit"; // Default value

    // Load the selected language file
    const translations = loadBlackrockTranslations(language); // Renamed function to avoid conflict
    if (!translations) {
        return res.status(400).json({ success: false, message: 'Invalid or missing language file.' });
    }

    // Parse transaction amounts
    const transaction1Parsed = parseFloat(transaction1);
    const transaction2Parsed = parseFloat(transaction2);
    if (isNaN(transaction1Parsed) || isNaN(transaction2Parsed)) {
        return res.status(400).json({ success: false, message: 'Invalid transaction amounts.' });
    }

    const doc = new PDFDocument({ margin: 30 });
    const fileName = `receipt_${Date.now()}.pdf`;
    const filePath = path.join(__dirname, 'new receipts', fileName);
    const receiptUrl = `/new receipts/${fileName}`;
    const bgColor = '#F4F7FE';

    const stream = fs.createWriteStream(filePath);
    doc.pipe(stream);

    const translatedMonth = translations["month"] && translations["month"][month] ? translations["month"][month] : month;

    const translatedDay = translations["day"] && translations["day"][day] ? translations["day"][day] : day;


    // Header Background (Month and Year)
    doc.rect(0, 0, doc.page.width, 40).fill('#CAE5FF');
    doc.fontSize(18).fillColor('#47505F').text(`${translatedMonth} ${year}`, 0, 15, { align: 'center' });


    // Category (Always "profit")
    const categoryText = (translations["category"] && translations["category"]["PROFIT"]) 
    ? translations["category"]["PROFIT"].toUpperCase() 
    : "PROFIT";
    doc.fontSize(18).fillColor('#000').text(categoryText, 100, 85);

    // Left Date Block
    doc.roundedRect(40, 80, 50, 50, 10).fill('#E5F1FF').stroke();
    doc.fillColor('#525F68').fontSize(14).text(`${translatedDay}\n${date}`, -450, 90, { align: 'center' });


    // First Transaction (Credit)
    doc.roundedRect(440, 85, 150, 25, 10).fill(bgColor);
    doc.fontSize(18).fillColor('#52788F').text(`-${currency} ${transaction1Parsed.toFixed(2)}`, 350, 90, { align: 'right' });

    // BlackRock & Investments
    doc.fontSize(16).fillColor('#888').text(translations['blackrock_investments'], 220, 120, { align: 'right' });

    // Second Transaction (Debit)
    doc.roundedRect(440, 145, 150, 25, 10).fill(bgColor);
    doc.fontSize(18).fillColor('#52788F').text(`+${currency} ${transaction2Parsed.toFixed(2)}`, 350, 150, { align: 'right' });

    // Bank Name
    doc.fontSize(16).fillColor('#888').text(bankName, 120, 180, { align: 'right' });

    // Arrow Connector
    doc.image('./arrow-in-receipt.png', 300, 130, { width: 40, height: 40 });

    // Business Info Section
    doc.moveDown(5);
    doc.fontSize(14).fillColor('#888').text(translations['business'], 40, 200);
    doc.fontSize(16).fillColor('#888').text(`${translations['payment_to']} `, 40, 220, { continued: true })
        .fontSize(19).font('Times-Italic').text(paymentTo);

    // Finalize PDF
    doc.end();

    stream.on('finish', () => {
        res.json({ success: true, receiptUrl });
    });
});





app.get('/api/user-details', async (req, res) => {
    const { email } = req.query;

    try {
        // Fetch user details from the database
        const [rows] = await pool.query(
            'SELECT fullName, currency, account_number, swift_code, IBAN, sort_code, ach_routing_number FROM users WHERE email = ?',
            [email]
        );

        if (rows.length === 0) {
            return res.status(404).json({ success: false, message: 'User not found.' });
        }

        const user = rows[0];

        // Check for missing account details
        const detailsMissing = !user.account_number || (!user.swift_code && !user.ach_routing_number);

        res.json({
            success: true,
            accountName: user.fullName,
            currency: user.currency,
            accountNumber: user.account_number || null,
            swiftCode: user.swift_code || null,
            IBAN: user.IBAN || null,
            sortCode: user.sort_code || null,
            achRoutingNumber: user.ach_routing_number || null,
            detailsMissing, // Flag to indicate if any details are missing
        });
    } catch (error) {
        console.error('Error fetching user details:', error);
        res.status(500).json({ success: false, message: 'An error occurred while fetching user details.' });
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


const translationsFolder = path.join(__dirname, '../'); // Root directory

const loadTranslations = (lang) => {
    try {
        // Map 'sq' to 'albanian.json'
        const languageMap = {
            'sq': 'albanian.json',
            'en': 'english.json',
            'cy': 'welsh.json',
            'gd': 'scottish.json',
            'ga': 'irish.json',
            'kw': 'cornish.json',
            'fr': 'french.json',
            'jerriais': 'jerriais.json',
            'guern': 'Guernésiais.json',
            "gv": "manx.json",
            "es": "spanish.json",
            "ca": "catalan.json",
            "hr": "croatian.json",
            "nl": "dutch.json",
            "et": "estonian.json",
            "fi": "finnish.json",
            "gl": "galician.json",
            "de": "german.json",
            "el": "greek.json",
            "it": "italian.json",
            "la": "latin.json",
            "lv": "latvian.json",
            "lt": "lithuanian.json",
            "lb": "luxembourgish.json",
            "mt": "maltese.json",
            "me": "montenegrin.json",
            "pt": "portuguese.json",
            "sr": "serbian.json",
            "sk": "slovak.json",
            "sl": "slovenian.json",
            "sv": "swedish.json",
            "tr": "turkish-cyprus.json"
        };

        // Get the filename based on the language
        const fileName = languageMap[lang] || `${lang}.json`;

        // Get the full file path from the root directory
        const filePath = path.join(__dirname, fileName);

        // Check if the file exists in the root directory
        if (fs.existsSync(filePath)) {
            return JSON.parse(fs.readFileSync(filePath, 'utf8'));
        } else {
            throw new Error('Translation file not found');
        }
    } catch (error) {
        console.error(`Error loading translation file for ${lang}:`, error);
        return null;
    }
};


app.post('/generate-receipt', async (req, res) => {
    try {
        const {
            senderName,
            recipientName,
            accountNumber,
            withdrawalAmount,
            currency,
            bankName,
            date,
            email,
            logoUrl,
            language // Get selected language from request
        } = req.body;

        // Check if all required fields are present, including the 'language'
        if (!senderName || !recipientName || !accountNumber || !withdrawalAmount || !currency || !bankName || !date || !language) {
            return res.status(400).json({ message: 'All fields are required.' });
        }

        // Load translation for the selected language
        const translations = loadTranslations(language);
        if (!translations) {
            return res.status(400).json({ message: 'Language not supported or error loading translation.' });
        }

        // Generate transaction-related values
        const transactionHash = crypto.randomBytes(16).toString('hex');
        const transactionReference = `TXN-${Date.now()}-${Math.floor(1000 + Math.random() * 9000)}`;
        const transactionType = bankName.toLowerCase() === 'withdrawal' 
    ? translations.outwardTransfer 
    : translations.inwardTransfer;


        const pdfDoc = new PDFDocument();
        const receiptFileName = `receipt-${Date.now()}.pdf`;
        const receiptPath = path.join(__dirname, 'receipts', receiptFileName);

        // Ensure the 'receipts' directory exists
        if (!fs.existsSync(path.join(__dirname, 'receipts'))) {
            fs.mkdirSync(path.join(__dirname, 'receipts'));
        }

        const stream = fs.createWriteStream(receiptPath);
        pdfDoc.pipe(stream);

        const primaryColor = '#30334B';
        const secondaryColor = '#7078b3';

        // PDF content
        pdfDoc
            .image(logoUrl || 'default-logo.png', 50, 50, { width: 150 })
            .moveDown(1)
            .fontSize(24).fillColor(primaryColor).text(translations.receiptType, { align: 'center', font: 'Helvetica-Bold' })
            .moveDown(1)
            .fontSize(12).fillColor(secondaryColor).text(`${translations.date}: ${date}`, { align: 'right' })
            .moveDown(2)
            .fontSize(16).fillColor(primaryColor).text(translations.transactionDetails, { font: 'Helvetica-Bold' })
            .moveDown(1)
            .fontSize(12).fillColor(primaryColor)
            .text(`${translations.senderName}`, { continued: true }).text(senderName, { align: 'right' })
            .moveDown(1)
            .text(`${translations.recipientName}`, { continued: true }).text(recipientName, { align: 'right' })
            .moveDown(1)
            .text(`${translations.accountNumber}`, { continued: true }).text(accountNumber, { align: 'right' })
            .moveDown(1)
            .fontSize(16)
            .text(`${translations.amount}`, { continued: true }).text(`${currency} ${withdrawalAmount}`, { align: 'right' })
            .moveDown(1)
            .fontSize(12)
            .text(`${translations.transactionType}`, { continued: true }).text(transactionType, { align: 'right' })
            .moveDown(1)
            .fontSize(12)
            .text(`${translations.transactionReference}`, { continued: true }).text(transactionReference, { align: 'right' })
            .moveDown(1)
            .fontSize(12)
            .text(`${translations.transactionHash}`, { continued: true }).text(transactionHash, { align: 'right' })
            .moveDown(2)
            .fontSize(12)
            .fontSize(10).fillColor(secondaryColor).text(translations.thankYouMessage, { align: 'center', font: 'Helvetica-Bold' })
            .moveDown(1)
            .fontSize(12)
            .text(translations.termsAndConditions, { align: 'center' })
            .moveDown(1);

        const baseUrl = `${req.protocol}://${req.get('host')}`;
        const receiptUrl = `${baseUrl}/receipts/${receiptFileName}`;
        pdfDoc.text(`${translations.viewReceiptText}: ${receiptUrl}`, { link: receiptUrl, align: 'center' });

        pdfDoc.end();

        // Stream finish event
        stream.on('finish', () => {
            res.json({
                message: translations.successAlert,
                receiptUrl: receiptUrl,
                transactionHash: transactionHash,
                transactionReference: transactionReference
            });
        });

        // Stream error event
        stream.on('error', (err) => {
            console.error(err);
            res.status(500).json({ message: translations.errorAlert });
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: translations.generalError });
    }
});



const docPath = path.join(__dirname, 'receipts');
if (!fs.existsSync(docPath)) fs.mkdirSync(docPath);

app.post('/generate-fidelity-receipt', async (req, res) => {
  const {
    date,
    amount,
    currency,
    originAccount,
    originBank,
    destinationAccount,
    destinationBank
  } = req.body;

  const timestamp = Date.now();
  const fileName = `fidelity_${timestamp}.pdf`;
  const filePath = path.join(docPath, fileName);

  const doc = new PDFDocument({ size: 'A5', margin: 40 });
  const writeStream = fs.createWriteStream(filePath);
  doc.pipe(writeStream);

  // Background
  doc.rect(0, 0, doc.page.width, doc.page.height).fill('#080C12');
  doc.fillColor('white');

  // Logo
  doc.image('Frame 114.png', doc.page.width / 2 - 20, 40, { width: 30 });

  doc.moveDown(3);
  doc.fontSize(16).text('Fidelity Investments', { align: 'center' });

  doc.moveTo(30, 110).lineTo(doc.page.width - 30, 110).strokeColor('#6B7F9A').stroke();

  // Checkmark
  doc.image('checkmark.png', doc.page.width / 2 - 30, 130, { width: 50 });

  doc.moveDown(5);
  doc.fontSize(12).fillColor('white').text('Transaction in progress', { align: 'center' });
  doc.moveDown(0.5);
  doc.fontSize(20).font('Helvetica-Bold').text(`${amount} ${currency}`, { align: 'center' });

  doc.moveTo(30, 250).lineTo(doc.page.width - 30, 250).strokeColor('#6B7F9A').stroke();

  // Details
  doc.moveDown();
  doc.fontSize(10).fillColor('white').text(`${date}`, 30, 270);
  
// Debit section
doc.moveDown(0.5);
doc.fillColor('#FFB300').font('Helvetica-Bold').text('Debit Account', { align: 'right' });

doc.fillColor('white').font('Helvetica')
   .text(`Asset origin`, 30, 300)
   .font('Helvetica-Bold').text(originAccount, 270, 300, { align: 'right' });

doc.font('Helvetica')
   .text(``, 30, 315)
   .font('Helvetica-Bold').text(originBank, 280, 315, { align: 'right' });

// Credit section
doc.moveDown(0.5);
doc.fillColor('green').font('Helvetica-Bold').text('Credit account', { align: 'right' });

doc.fillColor('#D3D3D3').font('Helvetica')
   .text(`Asset destination`, 30, 345)
   .font('Helvetica-Bold').text(destinationAccount, 280, 345, { align: 'right' });

doc.font('Helvetica')
   .text(``, 30, 360
   )
   .font('Helvetica-Bold').text(destinationBank, 280, 360, { align: 'right' });


  doc.moveTo(30, 390).lineTo(doc.page.width - 30, 390).strokeColor('#6B7F9A').stroke();

  doc.end();

  writeStream.on('finish', () => {
    res.json({ success: true, file: `/receipts/${fileName}` });
  });
});



app.use('/receipts', express.static(path.join(__dirname, 'receipts')));


app.post("/newreceipt", (req, res) => {
  try {
    const {
      date,
      debitType,
      debitBank,
      creditBank,
      creditName,
      amount,
      currency
    } = req.body;

    // Generate 9-digit reference number
    const referenceNumber = Math.floor(100000000 + Math.random() * 900000000);

    // Setup PDF
    const doc = new PDFDocument({ size: "A4", margin: 30 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=receipt.pdf");
    doc.pipe(res);

    // ==========================
    // HEADER (Red Bar)
    // ==========================
    doc.rect(0, 0, doc.page.width, 60).fill("#30334B");
    doc.fillColor("#fff")
      .fontSize(20)
      .text("Vanguard Royal Enterprise", 0, 20, { align: "center", width: doc.page.width });

    // ==========================
    // SUCCESS BLOCK
    // ==========================
    doc.rect(30, 80, doc.page.width - 60, 90).fill("#f2f2f2");
    doc.image("checkmark.png", 40, 95, { width: 20, height: 20 });
    doc.fillColor("green").fontSize(18).text("Successful", 70, 98);

    doc.fillColor("black").fontSize(14).text(`Ref ${referenceNumber}`, 40, 120);
    doc.text(`${date}`, 40, 140);

    // ==========================
    // "TO" SECTION
    // ==========================
    doc.fillColor("black").fontSize(16).text("To", 40, 190);

    doc.fillColor("black").fontSize(16).text("To", 40, 190);

    const shareBoxWidth = 60;
    const shareBoxHeight = 22;
    const pageWidth = doc.page.width;
    const shareBoxX = pageWidth - shareBoxWidth - 40;
    const shareBoxY = 185;

    doc.roundedRect(shareBoxX, shareBoxY, shareBoxWidth, shareBoxHeight, 6).fill("#e0e0e0");
    doc.fillColor("black")
      .fontSize(12)
      .text("Share", shareBoxX, shareBoxY + 5, {
        width: shareBoxWidth,
        align: "center"
      });

    // ==========================
    // ACCOUNT DETAILS BLOCK
    // ==========================
    const boxY = 220;
    const boxWidth = doc.page.width - 60;
    const textRightMargin = 40;
    const textWidth = boxWidth - 200;

    doc.rect(30, boxY, boxWidth, 200).fill("#F5F5F5");

    doc.fillColor("black").fontSize(16).text("Asset origin", 40, boxY + 20);

    doc.fillColor("#FFB300").fontSize(16).text("Debit Account", 40, boxY + 20, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });
    doc.fillColor("black").fontSize(16).text(debitType, 40, boxY + 40, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });
    doc.fillColor("gray").fontSize(16).text(debitBank, 40, boxY + 60, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });

    doc.fillColor("black").fontSize(16).text("Asset destination", 40, boxY + 120);

    doc.fillColor("green").fontSize(16).text("Credit account", 40, boxY + 120, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });
    doc.fillColor("black").fontSize(16).text(creditBank, 40, boxY + 140, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });
    doc.fillColor("gray").fontSize(16).text(creditName, 40, boxY + 160, {
      width: boxWidth - textRightMargin - -20,
      align: "right"
    });

    // ==========================
    // AMOUNT SECTION (MODIFIED)
    // ==========================
    const amountY = 450;

    doc.fillColor("black").fontSize(16).text("Amount", 40, amountY, {
      width: doc.page.width - 80,
      align: "left"
    });

    // Clean commas before parsing
    const cleanAmount = amount.toString().replace(/,/g, "");
    const formattedAmount = Number(cleanAmount).toLocaleString(undefined, {
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    });

    doc.fillColor("black")
      .fontSize(20)
      .text(`${currency} ${formattedAmount}`, 40, amountY + 25, {
        width: doc.page.width - 80,
        align: "left"
      });

    // ==========================
    // MORE TRANSFER DETAILS LINK
    // ==========================
    doc.fillColor("red")
      .fontSize(16)
      .text("More transfer details >", 40, amountY + 85, {
        underline: true
      });

    doc.end();
  } catch (err) {
    console.error(err);
    res.status(500).send("Error generating receipt");
  }
});


// app.post("/newreceipt", (req, res) => {
//   try {
//     const {
//       date,
//       debitType,
//       debitBank,
//       creditBank,
//       creditName,
//       amount,
//       currency
//     } = req.body;

//     // Generate 9-digit reference number
//     const referenceNumber = Math.floor(100000000 + Math.random() * 900000000);

//     // Setup PDF
//     const doc = new PDFDocument({ size: "A4", margin: 30 });
//     res.setHeader("Content-Type", "application/pdf");
//     res.setHeader("Content-Disposition", "attachment; filename=receipt.pdf");
//     doc.pipe(res);

//     // ==========================
//     // HEADER (Red Bar)
//     // ==========================
//     doc.rect(0, 0, doc.page.width, 60).fill("#30334B");
//     doc.fillColor("#fff")
//    .fontSize(20)
//    .text("Vanguard Royal Enterprise", 0, 20, { align: "center", width: doc.page.width });


//     // ==========================
//     // SUCCESS BLOCK
//     // ==========================
//     doc.rect(30, 80, doc.page.width - 60, 90).fill("#f2f2f2");
//     // Replace this:
//     doc.image("checkmark.png", 40, 95, { width: 20, height: 20 }); // ✅ Use your image
//     doc.fillColor("green").fontSize(18).text("Successful", 70, 98);

//     doc.fillColor("black").fontSize(14).text(`Ref ${referenceNumber}`, 40, 120);
//     doc.text(`${date}`, 40, 140);

//     // ==========================
//     // "TO" SECTION
//     // ==========================
//     // "To" on the left
// doc.fillColor("black").fontSize(16).text("To", 40, 190);

// // "To" on the left
// doc.fillColor("black").fontSize(16).text("To", 40, 190);

// // Position for the Share box (far right)
// const shareBoxWidth = 60;
// const shareBoxHeight = 22;
// const pageWidth = doc.page.width;

// const shareBoxX = pageWidth - shareBoxWidth - 40; // 40px right margin
// const shareBoxY = 185; // Independent from other sections

// // Draw grey rounded rectangle
// // Use a solid grey (no alpha in hex)
// doc.roundedRect(shareBoxX, shareBoxY, shareBoxWidth, shareBoxHeight, 6).fill("#e0e0e0");

// // Share text
// doc.fillColor("black")
//    .fontSize(12)
//    .text("Share", shareBoxX, shareBoxY + 5, {
//      width: shareBoxWidth,
//      align: "center"
//    });



//     // ==========================
//     // ACCOUNT DETAILS BLOCK
//     // ==========================
// const boxY = 220;
// const boxWidth = doc.page.width - 60;
// const textRightMargin = 40; // right padding inside the box
// const textWidth = boxWidth - 200; // width for right-aligned texts

// // Background
// doc.rect(30, boxY, boxWidth, 200).fill("#F5F5F5");

// // Labels (left side)
// doc.fillColor("black").fontSize(16).text("Asset origin", 40, boxY + 20);

// // Debit account section (without sender name)
// doc.fillColor("#FFB300").fontSize(16).text("Debit Account", 40, boxY + 20, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });
// doc.fillColor("black").fontSize(16).text(debitType, 40, boxY + 40, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });
// doc.fillColor("gray").fontSize(16).text(debitBank, 40, boxY + 60, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });




// // Second block
// doc.fillColor("black").fontSize(16).text("Asset destination", 40, boxY + 120);

// doc.fillColor("green").fontSize(16).text("Credit account", 40, boxY + 120, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });
// doc.fillColor("black").fontSize(16).text(creditBank, 40, boxY + 140, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });
// doc.fillColor("gray").fontSize(16).text(creditName, 40, boxY + 160, {
//   width: boxWidth - textRightMargin - -20,
//   align: "right"
// });


//  const amountY = 450;

//     doc.fillColor("black").fontSize(16).text("Amount", 40, amountY, {
//       width: doc.page.width - 80,
//       align: "left"
//     });

//     doc.fillColor("black")
//       .fontSize(20)
//       .text(`${currency} ${parseFloat(amount).toFixed(2)}`, 40, amountY + 25, {
//         width: doc.page.width - 80,
//         align: "left"
//       });


//     // ==========================
// // MORE TRANSFER DETAILS LINK
// // ==========================
// doc.fillColor("red")
//    .fontSize(16)
//    .text("More transfer details >", 40, amountY + 85, {
//      underline: true
//    });



//     // End PDF
//     doc.end();
//   } catch (err) {
//     console.error(err);
//     res.status(500).send("Error generating receipt");
//   }
// });

const fontsPath = path.join(__dirname, "fonts");
const inriaRegular = path.join(fontsPath, "InriaSans-Regular.ttf");
const inriaBold = path.join(fontsPath, "InriaSans-Bold.ttf");

// Helper to trim wallet address / txid
function trimMiddle(str, front = 6, back = 5) {
  if (str.length <= front + back) return str;
  return `${str.slice(0, front)}...${str.slice(-back)}`;
}

app.post("/generate-withdrawal-receipt", (req, res) => {
  const {
    status,
    date,
    source,
    coin,
    withdrawAmount,
    networkFee,
    address,
    network,
    txid
  } = req.body;

  const doc = new PDFDocument({
    size: "A4",
    margin: 30,
    font: inriaRegular
  });
  let buffers = [];
  doc.on("data", buffers.push.bind(buffers));
  doc.on("end", () => {
    const pdfData = Buffer.concat(buffers);
    res.writeHead(200, {
      "Content-Length": Buffer.byteLength(pdfData),
      "Content-Type": "application/pdf",
      "Content-Disposition": "attachment; filename=withdrawal-receipt.pdf",
    }).end(pdfData);
  });

  // Register fonts
  doc.registerFont("InriaSans", inriaRegular);
  doc.registerFont("InriaSans-Bold", inriaBold);

  // Background
  doc.rect(0, 0, doc.page.width, doc.page.height).fill("#1E2329");
  doc.fillColor("#fff");

  // ==================
  // HEADER
  // ==================
  doc.fontSize(24).font("InriaSans-Bold").text("Withdrawal Details", 30, 30);

  // Close "X" icon
  const closeIcon = path.join(__dirname, "icons", "close.png");
  if (fs.existsSync(closeIcon)) {
    doc.image(closeIcon, doc.page.width - 50, 25, { width: 15, height: 15 });
  }

  // ==================
  // TIMELINE
  // ==================
  const startY = 100;
  const stepGap = 95;
  const leftX = 50;

  function drawDiamond(doc, x, y, size, bgColor, number, textColor = "#fff") {
    doc.save();
    doc.translate(x, y);
    doc.rotate(45);
    doc.rect(-size / 2, -size / 2, size, size).fill(bgColor);
    doc.restore();

    doc.fillColor(textColor).fontSize(14).font("InriaSans-Bold")
      .text(number, x - 5, y - 8, { width: 14, align: "center" });
  }

  const diamondSize = 22;
  const textOffsetX = 45;

  // Step 1
  drawDiamond(doc, leftX, startY, diamondSize, "#ffffff", "1", "#000000");
  doc.fillColor("#fff").fontSize(16).font("InriaSans-Bold")
    .text("Withdrawal order submitted", leftX + textOffsetX, startY - 14);
  doc.font("InriaSans").fillColor("#bbb").fontSize(16)
    .text(date, leftX + textOffsetX, startY + 12);

  // Step 2
  drawDiamond(doc, leftX, startY + stepGap, diamondSize, "#ffffff", "2", "#000000");
  doc.fillColor("#fff").fontSize(16).font("InriaSans-Bold")
    .text("System processing", leftX + textOffsetX, startY + stepGap - 14);
  doc.font("InriaSans").fillColor("#bbb").fontSize(16)
    .text(date, leftX + textOffsetX, startY + stepGap + 12);
  doc.fillColor("#bbb").fontSize(15)
    .text("Need help about crypto withdrawal?", leftX + textOffsetX, startY + stepGap + 32);
  doc.fillColor("#ffcc00").fontSize(15)
    .underline(leftX + textOffsetX, startY + stepGap + 52, 80, 15, { color: "#ffcc00" })
    .text("View FAQs", leftX + textOffsetX, startY + stepGap + 52);

  // Step 3
  drawDiamond(doc, leftX, startY + stepGap * 2, diamondSize, "#555", "3");
  doc.fillColor("#fff").fontSize(16).font("InriaSans-Bold")
    .text("Estimated withdrawal successful", leftX + textOffsetX, startY + stepGap * 2 - 14);
  doc.font("InriaSans").fillColor("#bbb").fontSize(16)
    .text(date + " (Estimated)", leftX + textOffsetX, startY + stepGap * 2 + 12);
  doc.fillColor("#bbb").fontSize(15).text(
    "Please note that you will receive an email once it is completed.",
    leftX + textOffsetX, startY + stepGap * 2 + 32
  );
  doc.fillColor("#ffcc00").fontSize(15)
    .underline(leftX + textOffsetX, startY + stepGap * 2 + 52, 100, 15, { color: "#ffcc00" })
    .text("Report Scam", leftX + textOffsetX, startY + stepGap * 2 + 52);

  // Divider
  doc.moveTo(30, startY + stepGap * 2 + 100)
    .lineTo(doc.page.width - 30, startY + stepGap * 2 + 100)
    .strokeColor("#333")
    .stroke();

  // ==================
  // DETAILS BLOCK
  // ==================
  const blockY = startY + stepGap * 2 + 130;
  const labelX = 40;
  const rightMargin = 40;
  let y = blockY;

  function alignRight() {
    return { width: doc.page.width - labelX - rightMargin, align: "right" };
  }

  // Status
  doc.fillColor("#bbb").fontSize(16).text("Status", labelX, y);
  doc.fillColor("#fff").font("InriaSans-Bold").fontSize(16).text(status, labelX, y, alignRight());
  y += 38;

  // Date
  doc.fillColor("#bbb").fontSize(16).text("Date", labelX, y);
  doc.fillColor("#fff").font("InriaSans").fontSize(16).text(date, labelX, y, alignRight());
  y += 38;

  // Source
  doc.fillColor("#bbb").fontSize(16).text("Source", labelX, y);
  doc.fillColor("#fff").fontSize(16).text(source, labelX, y, alignRight());
  y += 38;

  // Coin + icon
  doc.fillColor("#bbb").fontSize(16).text("Coin", labelX, y);
  const coinIcon = path.join(__dirname, "icons", `${coin.toLowerCase()}.png`);
  if (fs.existsSync(coinIcon)) {
    const textWidth = doc.widthOfString(coin);
    const textX = doc.page.width - rightMargin - textWidth;
    doc.image(coinIcon, textX - 22, y - 0, { width: 17, height: 17 });
    doc.fillColor("#fff").fontSize(16).text(coin, labelX, y, alignRight());
  } else {
    doc.fillColor("#fff").fontSize(16).text(coin, labelX, y, alignRight());
  }
  y += 38;

  // Withdraw amount
  doc.fillColor("#bbb").fontSize(16).text("Withdraw amount", labelX, y);
  doc.fillColor("#fff").fontSize(16).text(withdrawAmount, labelX, y, alignRight());
  y += 38;

  // Network fee
  doc.fillColor("#bbb").fontSize(16).text("Network fee", labelX, y);
  doc.fillColor("#fff").fontSize(16).text(networkFee, labelX, y, alignRight());
  y += 38;

// Address
doc.fillColor("#bbb").fontSize(16).text("Address", labelX, y);
const trimmedAddress = trimMiddle(address);
doc.fillColor("#fff").fontSize(16).text(trimmedAddress, labelX, y, alignRight());

// icons: link + copy
const linkIcon = path.join(__dirname, "icons", "link.png");
const copyIcon = path.join(__dirname, "icons", "copy.png");
if (fs.existsSync(linkIcon) && fs.existsSync(copyIcon)) {
  const addrWidth = doc.widthOfString(trimmedAddress);
  const addrX = doc.page.width - rightMargin - addrWidth;

  // link icon right after text
  doc.image(linkIcon, addrX - 22, y - 0, { width: 17, height: 17 });

  // copy icon after link
  doc.image(copyIcon, addrX - 44, y - 0, { width: 17, height: 17 });
}
y += 38;

// Network
doc.fillColor("#bbb").fontSize(16).text("Network", labelX, y);
doc.fillColor("#fff").fontSize(16).text(network, labelX, y, alignRight());
y += 38;

// TxID
doc.fillColor("#bbb").fontSize(16).text("TxID", labelX, y);
const trimmedTxid = trimMiddle(txid);
doc.fillColor("#fff").fontSize(16).text(trimmedTxid, labelX, y, alignRight());

if (fs.existsSync(linkIcon) && fs.existsSync(copyIcon)) {
  const txidWidth = doc.widthOfString(trimmedTxid);
  const txidX = doc.page.width - rightMargin - txidWidth;

  // link icon right after text
  doc.image(linkIcon, txidX - 22, y - 0, { width: 17, height: 17 });

  // copy icon after link
  doc.image(copyIcon, txidX - 44, y - 0, { width: 17, height: 17 });
}
y += 38;


  // ==================
  // FOOTER
  // ==================
  doc.fillColor("#ffcc00")
    .font("InriaSans-Bold")
    .fontSize(16)
    .underline(doc.page.width / 2 - 100, doc.page.height - 70, 200, 18, { color: "#ffcc00" })
    .text("Need help? Chat with us", 0, doc.page.height - 70, { align: "center" });

  doc.end();
});



// ✅ Load Inria Sans font
const inriaSans = path.join(__dirname, "fonts", "InriaSans-Regular.ttf");
if (!fs.existsSync(inriaSans)) {
  console.error("⚠️ Missing InriaSans-Regular.ttf in fonts/ folder");
}


app.post("/generate-simple-withdrawal", (req, res) => {
  try {
    let { amount, coin, completionTime } = req.body;

    if (!amount || !coin || !completionTime) {
      return res.status(400).send("Missing required fields");
    }

    // Clean commas in amount
    amount = amount.toString().replace(/,/g, "");

    // Create PDF
    const doc = new PDFDocument({ size: "A4", margin: 0 });
    res.setHeader("Content-Type", "application/pdf");
    res.setHeader("Content-Disposition", "attachment; filename=withdrawal-receipt.pdf");
    doc.pipe(res);

    // Background
    doc.rect(0, 0, doc.page.width, doc.page.height).fill("#1E2329");

    // Reset text fill
    doc.fillColor("#fff");

    // Font
    if (fs.existsSync(inriaSans)) {
      doc.font(inriaSans);
    }

    let pageCenter = doc.page.width / 2;

    // Hourglass icon
    const hourglassIcon = path.join(__dirname, "icons", "hourglass.png");
    if (fs.existsSync(hourglassIcon)) {
      doc.image(hourglassIcon, pageCenter - 30, 150, { width: 60, height: 60 });
    }

    // Withdrawal Processing text
    doc.fontSize(20).fillColor("#fff").text("Withdrawal Processing", 0, 230, { align: "center" });

    // Amount + Coin
    doc.fontSize(28).fillColor("#fff").font(inriaSans).text(`${amount} ${coin}`, 0, 270, { align: "center" });

    // Estimated completion time
    doc.fontSize(12).fillColor("#aaa").text(`Estimated completion time: ${completionTime}`, 0, 320, { align: "center" });

    // Info lines
    doc.moveDown(1);
    doc.fontSize(12).fillColor("#aaa").text(
      "You will receive an email once withdrawal is completed.",
      { align: "center" }
    );
    doc.moveDown(0.5);
    doc.fontSize(12).fillColor("#aaa").text(
      "View history for the latest updates.",
      { align: "center" }
    );

    // Yellow button at bottom
    const buttonWidth = 500;
    const buttonHeight = 40;
    const buttonX = pageCenter - buttonWidth / 2;
    const buttonY = doc.page.height - 100;

    doc.roundedRect(buttonX, buttonY, buttonWidth, buttonHeight, 8).fill("#F6C547");
    doc.fillColor("#000").fontSize(14).text("View History", buttonX, buttonY + 12, {
      align: "center",
      width: buttonWidth
    });

    doc.end();
  } catch (err) {
    console.error("PDF Generation Error:", err);
    res.status(500).send("Server Error while generating receipt");
  }
});




// Catch-all route for invalid paths
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Route not found' });
});

// // Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});

// const PORT = process.env.PORT || 8080;
// const HOST = '0.0.0.0';

// app.listen(PORT, HOST, () => {
//     console.log(`Server is running on http://${HOST}:${PORT}`);
// });