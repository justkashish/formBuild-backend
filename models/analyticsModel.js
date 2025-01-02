const mongoose = require("mongoose");

const analyticsSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    formName: {
        type: String,
        required: true,
    },
    folderName: {
        type: String,
        required: true,
    },
    view: {
        type: Number,
        default: 0,
    },
    start: {
        type: Number,
        default: 0,
    },
    completed: {
        type: Number,
        default: 0,
    },

});

module.exports = mongoose.model("Analytics", analyticsSchema);