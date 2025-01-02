const mongoose = require("mongoose");
const Form = require("../models/formModel");
const Folder = require("../models/folderModel");

const createForm = async(req, res) => {
    try {
        const { formName, folderName } = req.body;
        const { id } = req.params;

        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) : null;

        if (!userId) {
            return res.status(400).json({ message: "Invalid userId format" });
        }

        if (!formName || formName.includes("@")) {
            return res.status(400).json({
                message: "Invalid formName. The name must not include '@'.",
            });
        }

        const formattedFormName = `${formName}@${folderName}@${userId}`;
        const form = new Form({
            formName: formattedFormName,
            userId,
            folderName: `${folderName}@${userId}`,
        });

        await form.save();

        const formsByFolder = await Form.find({ userId }).select("formName folderName -_id");
        const folderForms = {};

        formsByFolder.forEach((form) => {
            const cleanedFolderName = form.folderName.split("@")[0];
            if (!folderForms[cleanedFolderName]) {
                folderForms[cleanedFolderName] = [];
            }
            const originalFormName = form.formName.split("@")[0];
            folderForms[cleanedFolderName].push(originalFormName);
        });

        const folders = await Folder.find({ userId }).select("name -_id");
        const cleanedFolders = folders.map((f) => f.name.split("@")[0]);

        res.status(200).json({
            folders: cleanedFolders,
            folderForms,
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error creating form", error });
    }
};

const deleteForm = async(req, res) => {
    try {
        const { formName, folderName } = req.body;
        const { id } = req.params;

        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) : null;

        if (!userId) {
            return res.status(400).json({ message: "Invalid userId format" });
        }

        const folderExists = await Folder.findOne({
            userId,
            name: `${folderName}@${userId}`,
        });
        if (!folderExists) {
            return res.status(404).json({ error: "Folder not found." });
        }

        const deletedForm = await Form.findOneAndDelete({
            userId,
            folderName: `${folderName}@${userId}`,
            formName: `${formName}@${folderName}@${userId}`,
        });

        if (!deletedForm) {
            return res.status(404).json({ error: "Form not found." });
        }

        await Analytics.deleteMany({
            userId,
            formName: `${formName}@${folderName}@${userId}`,
            folderName: `${folderName}@${userId}`,
        });

        await Response.deleteMany({
            userId,
            formName: `${formName}@${folderName}@${userId}`,
            folderName: `${folderName}@${userId}`,
        });

        const formsByFolder = await Form.find({ userId }).select("formName folderName -_id");

        const folderForms = {};
        formsByFolder.forEach((form) => {
            const cleanedFolderName = form.folderName.split("@")[0];
            if (!folderForms[cleanedFolderName]) {
                folderForms[cleanedFolderName] = [];
            }
            const originalFormName = form.formName.split("@")[0];
            folderForms[cleanedFolderName].push(originalFormName);
        });

        const folders = await Folder.find({ userId }).select("name -_id");
        const cleanedFolderNames = folders.map((f) => f.name.split("@")[0]);

        cleanedFolderNames.forEach((folder) => {
            if (!folderForms[folder]) {
                folderForms[folder] = [];
            }
        });

        res.status(200).json({ folders: cleanedFolderNames, folderForms });
    } catch (error) {
        console.error("Error deleting form or retrieving forms:", error.message);
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};

const updateFormContent = async(req, res) => {
    try {
        const { id } = req.params;
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) : null;

        if (!userId) {
            return res.status(400).json({ message: "Invalid userId format" });
        }

        const { formName, folderName, elements, newFormName } = req.body;

        if (!formName || !folderName) {
            return res.status(400).json({ error: "Missing required formName or folderName" });
        }

        const formattedFolderName = `${folderName}@${userId}`;
        const currentFormattedFormName = `${formName}@${folderName}@${userId}`;

        if (newFormName) {
            try {
                const newFormattedFormName = `${newFormName}@${folderName}@${userId}`;
                const existingForm = await Form.findOne({
                    formName: currentFormattedFormName,
                    userId,
                    folderName: formattedFolderName,
                });

                if (!existingForm) {
                    return res.status(404).json({ error: "Form not found" });
                }

                existingForm.formName = newFormattedFormName;

                await Analytics.updateMany({
                    userId,
                    formName: currentFormattedFormName,
                    folderName: formattedFolderName,
                }, { $set: { formName: newFormattedFormName } });

                await Response.updateMany({
                    userId,
                    formName: currentFormattedFormName,
                    folderName: formattedFolderName,
                }, { $set: { formName: newFormattedFormName } });

                await existingForm.save();
                return res.status(200).json({ message: "Form name updated successfully" });
            } catch (error) {
                console.error("Error updating form name:", error);
                return res.status(500).json({ error: "Server error" });
            }
        }

        if (!elements) {
            return res.status(400).json({ error: "Missing required elements field" });
        }

        const existingForm = await Form.findOne({
            formName: currentFormattedFormName,
            userId,
            folderName: formattedFolderName,
        });

        if (!existingForm) {
            return res.status(404).json({ error: "Form not found" });
        }

        existingForm.elements = elements;
        await existingForm.save();

        res.status(200).json({
            message: "Form updated successfully",
            form: existingForm,
        });
    } catch (error) {
        console.error("Error updating form:", error);
        res.status(500).json({ error: "Server error" });
    }
};

const getFormContent = async(req, res) => {
    try {
        const { id } = req.params;
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) : null;

        if (!userId) {
            return res.status(400).json({ message: "Invalid userId format" });
        }

        const { formName, folderName } = req.query;

        if (!formName || !folderName) {
            return res.status(400).json({ error: "Missing formName or folderName" });
        }

        const formattedFolderName = `${folderName}@${userId}`;
        const formattedFormName = `${formName}@${folderName}@${userId}`;

        const form = await Form.findOne({
            userId,
            formName: formattedFormName,
            folderName: formattedFolderName,
        });

        if (!form) {
            return res.status(404).json({ error: "Form not found" });
        }

        const cleanedFolderName = form.folderName.split("@")[0];

        res.status(200).json({
            formName: form.formName.split("@")[0],
            folderName: cleanedFolderName,
            elements: form.elements,
            responses: form.responses,
        });
    } catch (error) {
        console.error("Error fetching form data:", error);
        res.status(500).json({ error: "Server error" });
    }
};

module.exports = {
    createForm,
    deleteForm,
    updateFormContent,
    getFormContent,
};