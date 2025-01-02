const mongoose = require("mongoose");


const responseSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
    },
    folderName: {
        type: String,
        required: true,
    },
    formName: {
        type: String,
        required: true,
    },
    user: {
        type: Number,
        required: true,
        default: 0,
    },

    buttonType: {
        type: String,
        required: true,
    },
    content: {
        type: String,
    },
    response: {
        type: String,
    },
    order: {
        type: Number,
        required: true,
    },
    timestamp: {
        type: Date,
        default: Date.now,
    },

});



module.exports = mongoose.model("Response", responseSchema);