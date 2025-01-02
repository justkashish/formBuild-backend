const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");

dotenv.config();

const ConnectDB = async(retries = 5, delay = 5000) => {
    if (!process.env.CONNECTION_STRING) {
        console.error("Missing CONNECTION_STRING environment variable");
        process.exit(1);
    }

    while (retries) {
        try {
            await mongoose.connect(process.env.CONNECTION_STRING);
            console.log("Successfully Connected with MongoDB");
            return;
        } catch (error) {
            retries -= 1;
            console.error(`Connection failed. Retrying... (${retries} retries left)`, error.message);
            if (retries === 0) {
                console.error("All retries exhausted. Server shutting down.");
                process.exit(1);
            }
            await new Promise((resolve) => setTimeout(resolve, delay));
        }
    }
};

module.exports = ConnectDB;