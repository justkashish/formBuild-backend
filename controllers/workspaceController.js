const mongoose = require("mongoose");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const addWorkSpaces = async(req, res) => {
    const { id } = req.params;
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    const { email, permission } = req.body;
    if (!email || !permission) {
        return res.status(400).json({ error: "Email and permission are required." });
    }

    try {
        const recipient = await User.findOne({ email });
        if (!recipient) {
            return res.status(404).json({ error: "User with provided email not found." });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        let workspaceAccessToken;
        try {
            workspaceAccessToken = generateAccessToken(user.email, permission);
        } catch (error) {
            console.error("Error generating access token:", error);
            return res.status(500).json({ error: "Failed to generate access token." });
        }

        if (!recipient.accessibleWorkspace) {
            recipient.accessibleWorkspace = [];
        }

        const workspaceExists = recipient.accessibleWorkspace.some(
            (workspace) => workspace.userId.toString() === userId.toString()
        );

        if (workspaceExists) {
            return res.status(400).json({ error: "Workspace already shared with this user." });
        }

        recipient.accessibleWorkspace.push({
            userId: userId,
            workspaceAccessToken: workspaceAccessToken,
        });

        await recipient.save();
        return res.status(200).json({
            message: "Workspace shared successfully.",
            username: recipient.username,
        });
    } catch (error) {
        console.error("Error sharing workspace:", error);
        return res.status(500).json({ error: "Internal server error." });
    }
};

const getWorkSpaces = async(req, res) => {
    const { id } = req.params;
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        const workspaceDetails = await Promise.all(
            user.accessibleWorkspace.map(async(workspace) => {
                try {
                    const decodedToken = jwt.verify(
                        workspace.workspaceAccessToken,
                        process.env.WORKSPACE_ACCESS_TOKEN_SECRET
                    );

                    const email = decodedToken.email;
                    const recipient = await User.findOne({ email });

                    if (recipient) {
                        return {
                            userId: workspace.userId,
                            username: recipient.username,
                            permission: decodedToken.permission,
                        };
                    } else {
                        return {
                            userId: workspace.userId,
                            error: `No user found for email: ${email}`,
                        };
                    }
                } catch (error) {
                    console.error("Token verification error:", error.message);
                    return {
                        userId: workspace.userId,
                        error: "Invalid or expired token.",
                    };
                }
            })
        );

        const currentUserWorkspace = {
            userId: userId.toString(),
            username: user.username,
            permission: "edit",
        };

        workspaceDetails.unshift(currentUserWorkspace);

        return res.status(200).json({
            message: "Workspaces fetched successfully",
            workspaces: workspaceDetails,
        });
    } catch (error) {
        console.error("Error fetching workspaces:", error.message);
        return res.status(500).json({ message: "Internal server error." });
    }
};

module.exports = { addWorkSpaces, getWorkSpaces };