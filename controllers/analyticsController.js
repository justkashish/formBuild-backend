const mongoose = require("mongoose");
const Analytics = require("../models/analyticsModel");

const updateAnalytics = async(req, res) => {
    const { id } = req.params;
    const { folderName, formName, analytics } = req.body;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        if (!["view", "start", "completed"].includes(analytics)) {
            return res.status(400).json({ message: "Invalid analytics type" });
        }

        const formattedFolderName = `${folderName}@${userId}`;
        const formattedFormName = `${formName}@${formattedFolderName}`;

        const updateOperation = {
            $inc: {
                [analytics]: 1
            }
        };

        const result = await Analytics.findOneAndUpdate({
                userId,
                folderName: formattedFolderName,
                formName: formattedFormName,
            },
            updateOperation, { new: true, upsert: true }
        );

        res.status(200).json({
            message: "Analytics updated successfully",
            data: {
                folderName: formattedFolderName.split("@")[0],
                formName: formattedFormName.split("@")[0],
                analytics: result,
            },
        });
    } catch (error) {
        console.error("Error updating analytics:", error);
        res.status(500).json({
            message: "Internal server error",
            error: error.message,
        });
    }
};

const getAnalytics = async(req, res) => {
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

        const analyticsData = await Analytics.findOne({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        });

        if (!analyticsData) {
            return res.status(404).json({ message: "Analytics data not found" });
        }

        res.status(200).json({
            folderName,
            formName,
            view: analyticsData.view || 0,
            start: analyticsData.start || 0,
            completed: analyticsData.completed || 0,
        });
    } catch (error) {
        console.error("Error fetching analytics:", error);
        res.status(500).json({ message: "Server error", error: error.message });
    }
};

module.exports = {
    updateAnalytics,
    getAnalytics,
};