const express = require("express");
const router = express.Router();
const {
    getUser,
    updateUser,
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
    addWorkSpaces,
    getWorkSpaces


} = require("../controllers/index.js");

router.get("/user/:id", getUser);
router.put("/user/:id", updateUser);
router.get("/", (req, res) => res.send("Authenticated"));
router.post("/folder/:id", createFolder);
router.delete("/folder/:id", deleteFolder);
router.post("/form/:id", createForm);
router.delete("/form/:id", deleteForm);
router.put("/form/:id", updateFormContent);
router.get("/form/:id", getFormContent);
router.post("/form/response/:id", addFormResponses);
router.get("/form/response/:id", getFormResponses);
router.put("/analytics/:id", updateAnalytics);
router.get("/analytics/:id", getAnalytics);
router.post("/access/workspaces/:id", addWorkSpaces);
router.get("/access/workspaces/:id", getWorkSpaces);
module.exports = router;