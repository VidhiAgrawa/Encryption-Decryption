const mongoose = require('mongoose');
const Schema = mongoose.Schema;

// This is our database "table"
// We only store the *encrypted* data string.
// We NEVER store the password.
const noteSchema = new Schema({
  encryptedData: {
    type: String,
    required: true
  }
}, {
  // Automatically add 'createdAt' and 'updatedAt' fields
  timestamps: true
});

module.exports = mongoose.model('Note', noteSchema);
