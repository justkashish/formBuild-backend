// index.js (to combine all controllers)
const userController = require('./userController');
const workspaceController = require('./workspaceController');
const folderController = require('./folderController');
const formController = require('./formController');
const responseController = require('./responseController');
const analyticsController = require('./analyticsController');

module.exports = {
    ...userController,
    ...workspaceController,
    ...folderController,
    ...formController,
    ...responseController,
    ...analyticsController,
};