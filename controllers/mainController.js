const express = require("express");
const mongoose = require("mongoose");
const User = require("../models/userModel");
const Folder = require("../models/folderModel");
const Form = require("../models/formModel");
const Response = require("../models/responseModel");
const Analytics = require("../models/analyticsModel");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const jwtExpiresIn = "7200m";

const generateAccessToken = (email, permission) => {
    return jwt.sign({ email, permission },
        process.env.WORKSPACE_ACCESS_TOKEN_SECRET, {
            expiresIn: jwtExpiresIn,
        }
    );
};


const addWorkSpaces = async(req, res) => {
    const { id } = req.params;

    // Validate, convert ID
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    const { email, permission } = req.body;
    console.log(email, permission);
    if (!email || !permission) {
        return res
            .status(400)
            .json({ error: "Email and permission are required." });
    }

    try {
        // Check if email exists
        const recipient = await User.findOne({ email });
        if (!recipient) {
            return res
                .status(404)
                .json({ error: "User with provided email not found." });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // Generate new JWT accessToken
        let workspaceAccessToken;
        try {
            workspaceAccessToken = generateAccessToken(
                user.email,
                permission
            );
        } catch (error) {
            console.error("Error generating access token:", error);
            return res
                .status(500)
                .json({ error: "Failed to generate access token." });
        }

        // Ensure accessibleWorkspace exists
        if (!recipient.accessibleWorkspace) {
            recipient.accessibleWorkspace = [];
        }

        // Check if the ownerId is already in accessibleWorkspace
        const workspaceExists = recipient.accessibleWorkspace.some(
            (workspace) => workspace.userId.toString() === userId.toString()
        );

        if (workspaceExists) {
            return res
                .status(400)
                .json({ error: "Workspace already shared with this user." });
        }

        // Add ownerId and accessToken to accessibleWorkspace
        recipient.accessibleWorkspace.push({
            userId: userId,
            workspaceAccessToken: workspaceAccessToken,
        });

        // Save the updated user document
        await recipient.save();
        console.log(recipient);
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

    // Validate and convert the ID
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Fetch the user by ID
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found." });
        }

        const accessibleWorkspace = user.accessibleWorkspace;

        // Map to fetch workspace details
        const workspaceDetails = await Promise.all(
            accessibleWorkspace.map(async(workspace) => {
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

        // Add current user as the first workspace with "edit" permission
        const currentUserWorkspace = {
            userId: userId.toString(),
            username: user.username,
            permission: "edit",
        };

        // Prepend the current user workspace to the workspaceDetails array
        workspaceDetails.unshift(currentUserWorkspace);

        // Return workspace details
        return res.status(200).json({
            message: "Workspaces fetched successfully",
            workspaces: workspaceDetails,
        });
    } catch (error) {
        console.error("Error fetching workspaces:", error.message);
        return res
            .status(500)
            .json({ message: "Internal server error." });
    }
};




const getUser = async(req, res) => {
    const { id } = req.params;
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    // Validate and convert the ID from request parameters
    const userIdFromParams = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userIdFromParams) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    if (!token) {
        return res
            .status(401)
            .json({ message: "Unauthorized: Access token is missing" });
    }

    try {
        // Decode the token
        const decodedToken = jwt.verify(
            token,
            process.env.ACCESS_TOKEN_SECRET
        );
        const userIdFromToken = decodedToken && decodedToken.id ? decodedToken.id : null;


        if (!mongoose.Types.ObjectId.isValid(userIdFromToken)) {
            return res
                .status(403)
                .json({ message: "Invalid or corrupted token." });
        }

        // Check if the `userId` in the token matches the `userId` in params
        if (!userIdFromParams.equals(
                new mongoose.Types.ObjectId(userIdFromToken)
            )) {
            const tokenUser = await User.findById(
                new mongoose.Types.ObjectId(userIdFromToken)
            );
            if (!tokenUser) {
                return res.status(404).json({ error: "User not found." });
            }

            // Check if the `userIdFromParams` exists in the `accessibleWorkspaces` array of the user from the token
            const hasAccess = tokenUser.accessibleWorkspace.some(
                (workspace) => workspace.userId.equals(userIdFromParams)
            );

            if (!hasAccess) {
                return res
                    .status(403)
                    .json({
                        error: "Access denied: No permission to access this user.",
                    });
            }
        }

        // Fetch the user by ID and exclude the password field explicitly
        const user = await User.findById(userIdFromParams).select(
            "-password"
        );

        if (!user) {
            return res.status(404).json({ error: "User not found." });
        }

        // Fetch all folders associated with the userId
        const folders = await Folder.find({
            userId: userIdFromParams,
        }).select("name -_id");

        // Initialize an object to hold folder-wise forms
        const folderForms = {};

        // Iterate through folders to fetch forms associated with each
        for (const folder of folders) {
            const forms = await Form.find({
                userId: userIdFromParams,
                folderName: folder.name,
            }).select("formName -_id");

            // Process the `formName` to extract the original name before returning
            folderForms[folder.name] = forms.map(
                (form) => form.formName.split("@")[0]
            );
        }

        // Respond with the user data and structured folder-to-forms mapping
        // Strip @userId from folder names and form names in the response
        const responseFolderForms = Object.keys(folderForms).reduce(
            (acc, folder) => {
                // Remove @userId from the folder name
                const cleanFolderName = folder.split("@")[0];
                // Map the forms for this folder, removing @userId from each form name
                acc[cleanFolderName] = folderForms[folder].map(
                    (form) => form.split("@")[0]
                );
                return acc;
            }, {}
        );

        res.status(200).json({
            user: user.toObject(),
            folders: folders.map((f) => f.name.split("@")[0]), // Removing @userId from folder names
            folderForms: responseFolderForms, // Clean folder names and form names
        });
    } catch (error) {
        // Handle errors (token decoding, DB queries, etc.)
        console.error(
            "Error fetching user or validating access:",
            error.message
        );
        res.status(500).json({
            error: "An unexpected error occurred while fetching the user, folders, or forms.",
        });
    }
};




const updateUser = async(req, res) => {
    const { id } = req.params;
    const { username, email, password, newPassword, theme } = req.body;

    // Validate and convert the ID
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }
    try {
        // Find the user by ID
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ error: "User not found" });
        }

        // Check if password and newPassword are provided
        if (password && newPassword) {
            // Verify the current password
            const isMatch = await user.comparePassword(
                password,
                user.password
            );
            if (!isMatch) {
                return res
                    .status(401)
                    .json({ error: "Invalid current password" });
            }

            // Hash the new password

            // Update the user's password, username, and email
            user.password = newPassword;
            if (username) user.username = username;
            if (email) user.email = email;
        } else {
            // If no password verification is needed, just update username and email
            if (username) user.username = username;
            if (email) user.email = email;
        }
        if (theme) {
            user.theme = theme;
        }
        // Save the updated user
        await user.save();

        res.status(200).json({ message: "User updated successfully" });
    } catch (error) {
        console.error("Error updating user:", error.message);
        res
            .status(500)
            .json({ error: "An error occurred while updating the user" });
    }
};
const createFolder = async(req, res) => {
    const { folderName } = req.body;
    const { id } = req.params; // userId

    // Validate userId
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    // Check if folderName contains the '@' symbol
    if (folderName.includes("@")) {
        return res
            .status(400)
            .json({ message: "Folder name cannot contain the '@' symbol" });
    }

    try {
        // Create a new folder associated with the userId in the format folderName@userId
        const folderNameWithUserId = `${folderName}@${userId}`;
        const newFolder = new Folder({
            name: folderNameWithUserId,
            userId,
        });
        await newFolder.save();

        // Retrieve all folders associated with the userId
        const userFolders = await Folder.find({ userId }).select("name"); // Only select folder names

        // Map to get an array of folder names in the original format (without the @userId part)
        const folderNames = userFolders.map(
            (folder) => folder.name.split("@")[0]
        );

        // Respond with the array of folder names
        res.status(201).json(folderNames);
    } catch (error) {
        // Log the error for debugging
        console.error(
            "Error creating folder or retrieving folders:",
            error.message
        );

        // Handle server errors
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};

const deleteFolder = async(req, res) => {
    const { folderName } = req.body; // Extract folderName from request body
    const { id } = req.params; // Extract userId from URL parameters
    console.log("folderName:", folderName);

    // Validate userId
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Append userId to folderName for uniqueness
        const formattedFolderName = `${folderName}@${userId}`;

        // Delete the folder associated with the formattedFolderName and userId
        const deletedFolder = await Folder.findOneAndDelete({
            name: formattedFolderName,
            userId,
        });

        if (!deletedFolder) {
            return res.status(404).json({ error: "Folder not found." });
        }

        // Find all forms associated with the folder and userId
        const formsToDelete = await Form.find({
            folderName: formattedFolderName,
            userId,
        });

        // Extract form names to delete responses and analytics
        const formNamesToDelete = formsToDelete.map(
            (form) => form.formName
        );

        // Delete all forms associated with the folder
        await Form.deleteMany({
            folderName: formattedFolderName,
            userId,
        });

        // Delete associated responses
        await Response.deleteMany({
            folderName: formattedFolderName,
            userId,
            formName: { $in: formNamesToDelete },
        });

        // Delete associated analytics
        await Analytics.deleteMany({
            folderName: formattedFolderName,
            userId,
            formName: { $in: formNamesToDelete },
        });

        // Retrieve the remaining forms for the user
        const formsByFolder = await Form.find({ userId }).select(
            "formName folderName -_id"
        );

        // Build a folder-to-forms mapping
        const folderForms = {};
        formsByFolder.forEach((form) => {
            const originalFolderName = form.folderName.split("@")[0]; // Remove userId from folderName
            if (!folderForms[originalFolderName]) {
                folderForms[originalFolderName] = [];
            }
            folderForms[originalFolderName].push(
                form.formName.split("@")[0]
            );
        });

        // Include folders without forms
        const folders = await Folder.find({ userId }).select("name -_id");
        const folderNames = folders.map(
            (folder) => folder.name.split("@")[0] // Remove userId from folderName
        );

        folderNames.forEach((originalFolderName) => {
            if (!folderForms[originalFolderName]) {
                folderForms[originalFolderName] = []; // Ensure empty folders are represented
            }
        });
        console.log(folderForms);
        // Respond with updated folder data
        res.status(200).json({
            folders: folderNames, // folder names without userId part
            folderForms,
        });
    } catch (error) {
        // Log the error for debugging
        console.error(
            "Error deleting folder or retrieving folders:",
            error.message
        );

        // Handle server errors
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};

// Create a new form
const createForm = async(req, res) => {
    try {
        const { formName, folderName } = req.body; // Extract data from the request body
        const { id } = req.params; // userId

        // Validate userId
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) :
            null;

        if (!userId) {
            return res
                .status(400)
                .json({ message: "Invalid userId format" });
        }

        // Validate formName
        if (!formName || formName.includes("@")) {
            return res.status(400).json({
                message: "Invalid formName. The name must not include '@'.",
            });
        }

        // Generate the formatted formName (includes folderName and userId)
        const formattedFormName = `${formName}@${folderName}@${userId}`;
        console.log("formattedFormName", formattedFormName);

        // Create a new form linked to the folder and user
        const form = new Form({
            formName: formattedFormName,
            userId,
            folderName: `${folderName}@${userId}`, // Store folder name with @userId format
        });

        await form.save(); // Save the form

        // Retrieve all forms grouped by their folders
        const formsByFolder = await Form.find({ userId }).select(
            "formName folderName -_id"
        );

        const folderForms = {};
        formsByFolder.forEach((form) => {
            // Clean the folder name (remove @userId)
            const cleanedFolderName = form.folderName.split("@")[0];

            if (!folderForms[cleanedFolderName]) {
                folderForms[cleanedFolderName] = [];
            }

            // Split the formatted formName and return only the original name (remove @userId)
            const originalFormName = form.formName.split("@")[0];
            folderForms[cleanedFolderName].push(originalFormName);
        });

        // Retrieve all folder names associated with the user and remove @userId from the folder name
        const folders = await Folder.find({ userId }).select("name -_id");

        // Clean the folder names (remove @userId part)
        const cleanedFolders = folders.map((f) => f.name.split("@")[0]);

        // Respond with the folder names array and folder-to-forms mapping
        res.status(200).json({
            folders: cleanedFolders, // Return cleaned folder names
            folderForms, // Return folder-wise forms with cleaned folder names
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: "Error creating form", error });
    }
};



const deleteForm = async(req, res) => {
    try {
        const { formName, folderName } = req.body; // Extract data from the request body
        const { id } = req.params; // userId

        // Validate userId
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) :
            null;

        if (!userId) {
            return res
                .status(400)
                .json({ message: "Invalid userId format" });
        }

        // Check if folder exists
        const folderExists = await Folder.findOne({
            userId,
            name: `${folderName}@${userId}`, // Check formatted folderName
        });
        if (!folderExists) {
            return res.status(404).json({ error: "Folder not found." });
        }

        // Delete the specified form (using the full formatted formName)
        const deletedForm = await Form.findOneAndDelete({
            userId,
            folderName: `${folderName}@${userId}`, // Match formatted folderName
            formName: `${formName}@${folderName}@${userId}`, // Match formatted formName
        });

        if (!deletedForm) {
            return res.status(404).json({ error: "Form not found." });
        }

        // Delete corresponding analytics and responses
        await Analytics.deleteMany({
            userId,
            formName: `${formName}@${folderName}@${userId}`, // Match formatted formName
            folderName: `${folderName}@${userId}`, // Match formatted folderName
        });

        await Response.deleteMany({
            userId,
            formName: `${formName}@${folderName}@${userId}`, // Match formatted formName
            folderName: `${folderName}@${userId}`, // Match formatted folderName
        });

        // Fetch all forms and group them by cleaned folder name
        const formsByFolder = await Form.find({ userId }).select(
            "formName folderName -_id"
        );

        const folderForms = {};
        formsByFolder.forEach((form) => {
            // Clean the folder name (remove @userId)
            const cleanedFolderName = form.folderName.split("@")[0];

            if (!folderForms[cleanedFolderName]) {
                folderForms[cleanedFolderName] = [];
            }

            // Clean the form name (remove @folderName and @userId)
            const originalFormName = form.formName.split("@")[0];
            folderForms[cleanedFolderName].push(originalFormName);
        });

        // Include folders that have no forms (empty folders)
        const folders = await Folder.find({ userId }).select("name -_id");
        const cleanedFolderNames = folders.map(
            (f) => f.name.split("@")[0]
        ); // Clean folder names

        // Ensure every folder is represented, even if empty
        cleanedFolderNames.forEach((folder) => {
            if (!folderForms[folder]) {
                folderForms[folder] = []; // Initialize empty array for folders without forms
            }
        });

        // Respond with cleaned folder names and folder-to-forms mapping
        res
            .status(200)
            .json({ folders: cleanedFolderNames, folderForms });
    } catch (error) {
        console.error(
            "Error deleting form or retrieving forms:",
            error.message
        );
        res.status(500).json({
            error: "An unexpected error occurred while processing the request.",
        });
    }
};



const updateFormContent = async(req, res) => {
    try {
        console.log("Reaching updateFormContent");

        const { id } = req.params; // userId
        console.log(id);

        // Validate userId
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) :
            null;

        if (!userId) {
            return res
                .status(400)
                .json({ message: "Invalid userId format" });
        }

        // Destructure data from the request body
        const { formName, folderName, elements, newFormName } = req.body;
        console.log(formName, folderName, elements);

        // Validate required fields
        if (!formName || !folderName) {
            return res
                .status(400)
                .json({ error: "Missing required formName or folderName" });
        }

        // Generate the current formatted formName and folderName
        const formattedFolderName = `${folderName}@${userId}`;
        const currentFormattedFormName = `${formName}@${folderName}@${userId}`;

        if (newFormName) {
            try {
                // Generate the new formatted formName
                const newFormattedFormName = `${newFormName}@${folderName}@${userId}`;

                // Find the existing form using the current formatted formName
                const existingForm = await Form.findOne({
                    formName: currentFormattedFormName,
                    userId,
                    folderName: formattedFolderName,
                });

                if (!existingForm) {
                    return res.status(404).json({ error: "Form not found" });
                }

                // Update the form name
                existingForm.formName = newFormattedFormName;

                // Update related analytics and responses with the new formName
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
                return res
                    .status(200)
                    .json({ message: "Form name updated successfully" });
            } catch (error) {
                console.error("Error updating form name:", error);
                return res.status(500).json({ error: "Server error" });
            }
        }

        // Check if elements are provided for updating content
        if (!elements) {
            return res
                .status(400)
                .json({ error: "Missing required elements field" });
        }

        // Find the existing form using the formatted formName
        const existingForm = await Form.findOne({
            formName: currentFormattedFormName,
            userId,
            folderName: formattedFolderName,
        });

        if (!existingForm) {
            return res.status(404).json({ error: "Form not found" });
        }

        // Update the form fields
        existingForm.elements = elements;

        // Save the updated form
        await existingForm.save();

        // Send success response
        res.status(200).json({
            message: "Form updated successfully",
            form: existingForm,
        });
    } catch (error) {
        console.error("Error updating form:", error);
        res.status(500).json({ error: "Server error" });
    }
};




const addFormResponses = async(req, res) => {
    const { id } = req.params; // Extract userId from the URL parameters
    const { folderName, formName, responses } = req.body; // Extract folderName, formName, and responses from request body
    console.log("Received responses:", folderName, formName, responses);

    // Validate userId
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Append userId to folderName for uniqueness
        const formattedFolderName = `${folderName}@${userId}`;

        // Generate the formatted formName
        const formattedFormName = `${formName}@${formattedFolderName}`;

        // Check if the form exists
        const form = await Form.findOne({
            formName: formattedFormName,
            userId,
            folderName: formattedFolderName,
        });

        if (!form) {
            return res.status(404).json({ message: "Form not found" });
        }

        // Find the latest response by userId, formattedFolderName, and formattedFormName
        const latestResponse = await Response.findOne({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        }).sort({ timestamp: -1 });

        // Determine the last user value and increment it
        const lastUserValue = latestResponse ? latestResponse.user : 0;
        const newUser = lastUserValue + 1;

        // Save all responses
        const savedResponses = [];
        for (const resp of responses) {
            const { buttonType, response, order, timestamp } = resp;

            // Validate required fields in each response
            if (!order || !buttonType) {
                return res.status(400).json({
                    message: "order and buttonType are required for each response",
                });
            }

            // Check if the element exists in the form
            const element = form.elements.find(
                (el) => el.order === order && el.buttonType === buttonType
            );

            if (element) {
                // Prepare the new response
                const newResponse = new Response({
                    userId,
                    folderName: formattedFolderName,
                    formName: formattedFormName,
                    user: newUser,
                    buttonType,
                    content: element.content,
                    response,
                    order,
                    timestamp: new Date(timestamp), // Ensure timestamp is properly formatted
                });

                // Save and collect the response
                await newResponse.save();
                savedResponses.push(newResponse);
            } else {
                console.log(
                    `Element not found for order ${order} and buttonType ${buttonType}`
                );
            }
        }

        // Return the saved responses
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
    const { id } = req.params; // Extract userId from the URL parameters
    const { folderName, formName } = req.query; // Extract folderName and formName from query parameters
    console.log("reached", folderName, formName);

    // Validate userId
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Append userId to folderName to ensure uniqueness
        const formattedFolderName = `${folderName}@${userId}`;

        // Generate the formatted formName
        const formattedFormName = `${formName}@${formattedFolderName}`;

        // Fetch all responses for the given userId, folderName, and formatted formName
        const responses = await Response.find({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        });

        console.log("Responses:", responses);

        if (!responses || responses.length === 0) {
            return res.status(404).json({
                message: "No responses found for the given form",
            });
        }

        // Return the found responses
        res.status(200).json({
            message: "Responses fetched successfully",
            folderName, // Return cleaned folderName
            formName, // Return cleaned formName
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




const getFormContent = async(req, res) => {
    try {
        console.log("Reaching getFormContent");

        // Extract userId from route parameters
        const { id } = req.params;
        console.log("UserId:", id);

        // Validate userId
        const userId = mongoose.Types.ObjectId.isValid(id) ?
            new mongoose.Types.ObjectId(id) :
            null;

        if (!userId) {
            return res
                .status(400)
                .json({ message: "Invalid userId format" });
        }

        // Extract formName and folderName from query parameters
        const { formName, folderName } = req.query;
        console.log("formName:", formName, "folderName:", folderName);

        // Check if all required fields are provided
        if (!formName || !folderName) {
            return res
                .status(400)
                .json({ error: "Missing formName or folderName" });
        }

        // Generate the formatted folderName and formName for lookup
        const formattedFolderName = `${folderName}@${userId}`;
        const formattedFormName = `${formName}@${folderName}@${userId}`;

        // Query the database for the form using the formatted formName
        const form = await Form.findOne({
            userId,
            formName: formattedFormName,
            folderName: formattedFolderName,
        });

        if (!form) {
            return res.status(404).json({ error: "Form not found" });
        }

        // Remove formatting from folderName before sending response
        const cleanedFolderName = form.folderName.split("@")[0];

        // Return the form data, including responses
        res.status(200).json({
            formName: form.formName.split("@")[0], // Return only the original formName
            folderName: cleanedFolderName, // Return cleaned folderName
            elements: form.elements,
            responses: form.responses,
        });
    } catch (error) {
        console.error("Error fetching form data:", error);
        res.status(500).json({ error: "Server error" });
    }
};



const updateAnalytics = async(req, res) => {
    const { id } = req.params; // Extract user ID from the request parameters
    const { folderName, formName, analytics } = req.body; // Extract folderName, formName, and analytics from the request body

    // Validate the provided ID
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Validate the analytics type
        if (!["view", "start", "completed"].includes(analytics)) {
            return res
                .status(400)
                .json({ message: "Invalid analytics type" });
        }

        // Format the folderName to include the userId
        const formattedFolderName = `${folderName}@${userId}`;

        // Generate the formatted formName
        const formattedFormName = `${formName}@${formattedFolderName}`;

        // Define the update operation based on the analytics value
        const updateOperation = {
            $inc: {
                [analytics]: 1
            }
        };

        // Find the document to update or create a new one if it doesn't exist
        const result = await Analytics.findOneAndUpdate({
                userId,
                folderName: formattedFolderName,
                formName: formattedFormName,
            },
            updateOperation, { new: true, upsert: true } // Create a new document if one doesn't exist
        );

        console.log(result);

        // Send the updated document as the response
        res.status(200).json({
            message: "Analytics updated successfully",
            data: {
                folderName: formattedFolderName.split("@")[0], // Return cleaned folderName
                formName: formattedFormName.split("@")[0], // Return cleaned formName
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
    const { id } = req.params; // Extract user ID from URL params
    const { folderName, formName } = req.query; // Extract folder name and form name from query params

    // Validate userId
    const userId = mongoose.Types.ObjectId.isValid(id) ?
        new mongoose.Types.ObjectId(id) :
        null;

    if (!userId) {
        return res.status(400).json({ message: "Invalid userId format" });
    }

    try {
        // Append userId to folderName to ensure uniqueness
        const formattedFolderName = `${folderName}@${userId}`;

        // Generate the formatted formName for the query
        const formattedFormName = `${formName}@${formattedFolderName}`;

        // Query the analytics data
        const analyticsData = await Analytics.findOne({
            userId,
            folderName: formattedFolderName,
            formName: formattedFormName,
        });

        console.log("analyticsData:", analyticsData);

        if (!analyticsData) {
            return res
                .status(404)
                .json({ message: "Analytics data not found" });
        }

        // Send analytics data
        res.status(200).json({
            folderName, // Return the cleaned folderName
            formName, // Return the cleaned formName
            view: analyticsData.view || 0,
            start: analyticsData.start || 0,
            completed: analyticsData.completed || 0,
        });
    } catch (error) {
        // Handle errors
        console.error("Error fetching analytics:", error);
        res
            .status(500)
            .json({ message: "Server error", error: error.message });
    }
};


module.exports = {
    getUser,
    createFolder,
    deleteFolder,
    createForm,
    deleteForm,
    updateFormContent,
    getFormContent,
    addFormResponses,
    getFormResponses,
    updateAnalytics,
    getAnalytics,
    updateUser,
    addWorkSpaces,
    getWorkSpaces,
};