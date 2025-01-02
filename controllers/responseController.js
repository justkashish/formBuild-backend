const mongoose = require("mongoose");
const Response = require("../models/responseModel");
const Form = require("../models/formModel");

const addFormResponses = async(req, res) => {
    const { id } = req.params;
    const { folderName, formName, responses } = req.body;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        const formattedFolderName = `${folderName}@${userId}`;
        const formattedFormName = `${formName}@${formattedFolderName}`;

        const form = await Form.findOne({
            formName: formattedFormName,
            userId,
            folderName: formattedFolderName,
        });

        if (!form) {
            return res.status(404).json({ message: "Form not found" });
        }

        const latestResponse = await Response.findOne({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        }).sort({ timestamp: -1 });

        const lastUserValue = latestResponse ? latestResponse.user : 0;
        const newUser = lastUserValue + 1;

        const savedResponses = [];
        for (const resp of responses) {
            const { buttonType, response, order, timestamp } = resp;

            if (!order || !buttonType) {
                return res.status(400).json({
                    message: "order and buttonType are required for each response",
                });
            }

            const element = form.elements.find(
                (el) => el.order === order && el.buttonType === buttonType
            );

            if (element) {
                const newResponse = new Response({
                    userId,
                    folderName: formattedFolderName,
                    formName: formattedFormName,
                    user: newUser,
                    buttonType,
                    content: element.content,
                    response,
                    order,
                    timestamp: new Date(timestamp),
                });

                await newResponse.save();
                savedResponses.push(newResponse);
            } else {
                console.log(`Element not found for order ${order} and buttonType ${buttonType}`);
            }
        }

        res.status(200).json({
            message: "Responses added successfully",
            responses: savedResponses,
        });
    } catch (error) {
        console.error("Error adding responses:", error);
        res.status(500).json({
            message: "Error adding responses",
            error: error.message,
        });
    }
};

const getFormResponses = async(req, res) => {
    const { id } = req.params;
    const { folderName, formName } = req.query;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        const formattedFolderName = `${folderName}@${userId}`;
        const formattedFormName = `${formName}@${formattedFolderName}`;

        const responses = await Response.find({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        });

        if (!responses || responses.length === 0) {
            return res.status(404).json({
                message: "No responses found for the given form",
            });
        }

        res.status(200).json({
            message: "Responses fetched successfully",
            folderName,
            formName,
            responses,
        });
    } catch (error) {
        console.error("Error fetching responses:", error);
        res.status(500).json({
            message: "Error fetching responses",
            error: error.message,
        });
    }
};

module.exports = {
    addFormResponses,
    getFormResponses,
};