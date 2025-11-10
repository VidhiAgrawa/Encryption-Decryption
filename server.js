// 1. IMPORT DEPENDENCIES
require('dotenv').config(); // Load environment variables from .env file
const express = require('express');
const mongoose = require('mongoose');
const { encrypt, decrypt } = require('./cryptoLogic');
const Note = require('./models/Note');

// 2. INITIALIZE APP
const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true })); // Body parser
app.use(express.static('public')); // For any future CSS/JS

// 3. CONNECT TO DATABASE
mongoose.connect(process.env.MONGO_URI)
  .then(() => {
    console.log('Connected to MongoDB');
    app.listen(process.env.PORT || 3000, () => {
      console.log('Server is running on port 3000');
    });
  })
  .catch((err) => {
    console.error('Database connection failed', err);
    process.exit(1);
  });

// 4. DEFINE ROUTES

// --- Homepage: Show form to create a new note ---
app.get('/', (req, res) => {
  res.render('index');
});

// --- Handle Encryption and Saving ---
app.post('/encrypt', async (req, res) => {
  try {
    const { message, password } = req.body;

    if (!message || !password) {
      return res.render('index', { error: 'Message and password are required.' });
    }

    // Encrypt the message using our crypto logic
    const encryptedData = await encrypt(message, password);

    // Save the *encrypted* data to the database
    const note = new Note({
      encryptedData: encryptedData
    });
    await note.save();

    // Redirect to a page showing the new note's ID/link
    res.redirect(`/note/${note._id}`);

  } catch (error) {
    console.error(error);
    res.render('index', { error: 'Encryption failed.' });
  }
});

// --- Show the link for the newly created note ---
app.get('/note/:id', (req, res) => {
  const noteId = req.params.id;
  // Construct the full URL
  const noteUrl = `${req.protocol}://${req.get('host')}/decrypt/${noteId}`;
  res.render('note', { noteUrl, noteId });
});

// --- Show the decryption page for a specific note ---
app.get('/decrypt/:id', (req, res) => {
  // Render the decryption page, passing in the note ID
  res.render('decrypt', {
    noteId: req.params.id,
    error: null,
    decryptedMessage: null
  });
});

// --- Handle Decryption ---
app.post('/decrypt', async (req, res) => {
  const { noteId, password } = req.body;
  let error = null;
  let decryptedMessage = null;

  try {
    if (!noteId || !password) {
      error = 'Note ID and password are required.';
    } else {
      // 1. Find the note in the database
      const note = await Note.findById(noteId);

      if (!note) {
        error = 'Note not found. It may have been deleted or the link is wrong.';
      } else {
        // 2. Try to decrypt the data with the provided password
        // This will either work or throw an error (if password is wrong)
        decryptedMessage = await decrypt(note.encryptedData, password);
      }
    }
  } catch (err) {
    console.error(err);
    // If decryption fails (wrong password), cryptoLogic.js will throw error.
    error = 'Decryption failed. Probably the wrong password.';
  }

  // 3. Re-render the same page with the result
  res.render('decrypt', {
    noteId: noteId,
    error: error,
    decryptedMessage: decryptedMessage
  });
});
