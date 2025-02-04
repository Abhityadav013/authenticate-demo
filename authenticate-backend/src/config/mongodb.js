import mongoose from "mongoose";

const connectDB = async () => {
    try {
        await mongoose.connect(`${process.env.MONGODB_URI}/Authenticate`);

        console.log("Connected to database");

        mongoose.connection.on("error", (err) => {
            console.error("MongoDB connection error:", err);
        });

    } catch (error) {
        console.error("Error connecting to database:", error);
        process.exit(1); // Exit process with failure
    }
};

export default connectDB;
