const mongoose = require("mongoose");
const Folder = require("../models/folderModel");
const Form = require("../models/formModel");
const Response = require("../models/responseModel");
const Analytics = require("../models/analyticsModel");

const createFolder = async(req, res) => {
    const { folderName } = req.body;
    const { id } = req.params;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    if (folderName.includes("@")) {
        return res.status(400).json({ message: "Folder name cannot contain the '@' symbol" });
    }

    try {
        const folderNameWithUserId = `${folderName}@${userId}`;
        const newFolder = new Folder({
            name: folderNameWithUserId,
            userId,
        });
        await newFolder.save();

        const userFolders = await Folder.find({ userId }).select("name");
        const folderNames = userFolders.map((folder) => folder.name.split("@")[0]);

        res.status(201).json(folderNames);
    } catch (error) {
        console.error("Error creating folder or retrieving folders:", error.message);
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};

const deleteFolder = async(req, res) => {
    const { folderName } = req.body;
    const { id } = req.params;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        const formattedFolderName = `${folderName}@${userId}`;

        const deletedFolder = await Folder.findOneAndDelete({
            name: formattedFolderName,
            userId,
        });

        if (!deletedFolder) {
            return res.status(404).json({ error: "Folder not found." });
        }

        const formsToDelete = await Form.find({
            folderName: formattedFolderName,
            userId,
        });

        const formNamesToDelete = formsToDelete.map((form) => form.formName);

        await Form.deleteMany({
            folderName: formattedFolderName,
            userId,
        });

        await Response.deleteMany({
            folderName: formattedFolderName,
            userId,
            formName: { $in: formNamesToDelete },
        });

        await Analytics.deleteMany({
            folderName: formattedFolderName,
            userId,
            formName: { $in: formNamesToDelete },
        });

        const formsByFolder = await Form.find({ userId }).select("formName folderName -_id");
        const folderForms = {};

        formsByFolder.forEach((form) => {
            const originalFolderName = form.folderName.split("@")[0];
            if (!folderForms[originalFolderName]) {
                folderForms[originalFolderName] = [];
            }
            folderForms[originalFolderName].push(form.formName.split("@")[0]);
        });

        const folders = await Folder.find({ userId }).select("name -_id");
        const folderNames = folders.map((folder) => folder.name.split("@")[0]);

        folderNames.forEach((originalFolderName) => {
            if (!folderForms[originalFolderName]) {
                folderForms[originalFolderName] = [];
            }
        });

        res.status(200).json({
            folders: folderNames,
            folderForms,
        });
    } catch (error) {
        console.error("Error deleting folder or retrieving folders:", error.message);
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};

module.exports = { createFolder, deleteFolder };