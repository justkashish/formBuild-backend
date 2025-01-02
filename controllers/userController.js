const mongoose = require("mongoose");
const User = require("../models/userModel");
const jwt = require("jsonwebtoken");

const jwtExpiresIn = "7200m";

const generateAccessToken = (email, permission) => {
    return jwt.sign({ email, permission },
        process.env.WORKSPACE_ACCESS_TOKEN_SECRET, { expiresIn: jwtExpiresIn }
    );
};

const getUser = async(req, res) => {
    const { id } = req.params;
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    const userIdFromParams = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userIdFromParams) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    if (!token) {
        return res.status(401).json({ message: "Unauthorized: Access token is missing" });
    }

    try {
        const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        const userIdFromToken = decodedToken && decodedToken.id ? decodedToken.id : null;

        if (!mongoose.Types.ObjectId.isValid(userIdFromToken)) {
            return res.status(403).json({ message: "Invalid or corrupted token." });
        }

        if (!userIdFromParams.equals(new mongoose.Types.ObjectId(userIdFromToken))) {
            const tokenUser = await User.findById(new mongoose.Types.ObjectId(userIdFromToken));
            if (!tokenUser) {
                return res.status(404).json({ error: "User not found." });
            }

            const hasAccess = tokenUser.accessibleWorkspace.some(
                (workspace) => workspace.userId.equals(userIdFromParams)
            );

            if (!hasAccess) {
                return res.status(403).json({
                    error: "Access denied: No permission to access this user.",
                });
            }
        }

        const user = await User.findById(userIdFromParams).select("-password");

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        const folders = await Folder.find({ userId: userIdFromParams }).select("name -_id");
        const folderForms = {};

        for (const folder of folders) {
            const forms = await Form.find({
                userId: userIdFromParams,
                folderName: folder.name,
            }).select("formName -_id");

            folderForms[folder.name] = forms.map((form) => form.formName.split("@")[0]);
        }

        const responseFolderForms = Object.keys(folderForms).reduce((acc, folder) => {
            const cleanFolderName = folder.split("@")[0];
            acc[cleanFolderName] = folderForms[folder].map((form) => form.split("@")[0]);
            return acc;
        }, {});

        res.status(200).json({
            user: user.toObject(),
            folders: folders.map((f) => f.name.split("@")[0]),
            folderForms: responseFolderForms,
        });
    } catch (error) {
        console.error("Error fetching user or validating access:", error.message);
        res.status(500).json({
            error: "An unexpected error occurred while fetching the user, folders, or forms.",
        });
    }
};

const updateUser = async(req, res) => {
    const { id } = req.params;
    const { username, email, password, newPassword, theme } = req.body;

    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) : null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        if (password && newPassword) {
            const isMatch = await user.comparePassword(password, user.password);
            if (!isMatch) {
                return res.status(401).json({ error: "Invalid current password" });
            }
            user.password = newPassword;
        }

        if (username) user.username = username;
        if (email) user.email = email;
        if (theme) user.theme = theme;

        await user.save();
        res.status(200).json({ message: "User updated successfully" });
    } catch (error) {
        console.error("Error updating user:", error.message);
        res.status(500).json({ error: "An error occurred while updating the user" });
    }
};

module.exports = { getUser, updateUser };