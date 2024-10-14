const mongoose = require("mongoose");

const itemSchema = new mongoose.Schema({
    landf: String,
    title: String,
    type: String,
    description: String,
    location: String,
    date: Date,
    photo: String,
    phone: String
});

const Item = mongoose.model('Item', itemSchema);

const itemSchema2 = new mongoose.Schema({
    id: { type: String, required: true },
    description: { type: String, required: true },
    phone: { type: String, required: true }
});
const Item2 = mongoose.model('Item2', itemSchema2);

module.exports = {Item, Item2};