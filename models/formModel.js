const mongoose = require("mongoose");

const formElementSchema = new mongoose.Schema({
    buttonType: {
        type: String,
        required: true,
    },
    id: {
        type: String,
        required: true,
    },
    content: {
        type: String,
        required: function() {
            return this.type === "text" || this.type === "image";
        },
    },
    order: {
        type: Number,
        required: true,
    },
});

const formSchema = new mongoose.Schema({
    formName: {
        type: String,
        required: true,
    },
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
    },
    folderName: {
        type: String,
        required: true,
    },
    elements: [formElementSchema],

    createdAt: {
        type: Date,
        default: Date.now,
    },
});

module.exports = mongoose.model("Form", formSchema);