const express = require("express");
const app = express();

const database = require("./db/db");
const cookieParser = require("cookie-parser");
const cors = require("cors");
const dotenv = require("dotenv");

dotenv.config();

database.connect();
app.use(express.json());
app.use(cookieParser());
app.use(cors());

const userRoutes = require("./routes/User");

//routes
app.use("/api/v1/auth", userRoutes);

//def route

app.get("/", (req, res) => {
  return res.json({
    success: true,
    message: "Your server is up and running....",
  });
});

const PORT = process.env.PORT || 5000;

app.listen(process.env.PORT, () => {
  console.log(`App is running at ${PORT}`);
});
