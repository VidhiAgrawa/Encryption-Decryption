require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const { encrypt, decrypt } = require('./cryptoLogic');
const Note = require('./models/Note');

const app = express();
app.set('view engine', 'ejs');
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

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

app.get('/', (req, res) => {
  res.render('index');
});

app.post('/encrypt', async (req, res) => {
  try {
    const { message, password } = req.body;

    if (!message || !password) {
      return res.render('index', { error: 'Message and password are required.' });
    }

    const encryptedData = await encrypt(message, password);

    const note = new Note({
      encryptedData: encryptedData
    });
    await note.save();

    res.redirect(`/note/${note._id}`);

  } catch (error) {
    console.error(error);
    res.render('index', { error: 'Encryption failed.' });
  }
});

app.get('/note/:id', (req, res) => {
  const noteId = req.params.id;
  const noteUrl = `${req.protocol}://${req.get('host')}/decrypt/${noteId}`;
  res.render('note', { noteUrl, noteId });
});

app.get('/decrypt/:id', (req, res) => {
  res.render('decrypt', {
    noteId: req.params.id,
    error: null,
    decryptedMessage: null
  });
});

app.post('/decrypt', async (req, res) => {
  const { noteId, password } = req.body;
  let error = null;
  let decryptedMessage = null;

  try {
    if (!noteId || !password) {
      error = 'Note ID and password are required.';
    } else {
      const note = await Note.findById(noteId);

      if (!note) {
        error = 'Note not found. It may have been deleted or the link is wrong.';
      } else {
        decryptedMessage = await decrypt(note.encryptedData, password);
      }
    }
  } catch (err) {
    console.error(err);
    error = 'Decryption failed. Probably the wrong password.';
  }

  res.render('decrypt', {
    noteId: noteId,
    error: error,
    decryptedMessage: decryptedMessage
  });
});
