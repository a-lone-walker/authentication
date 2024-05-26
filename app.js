const express = require("express");
const path = require("path");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcrypt");

const app = express();
app.use(express.json());

let dbPath = path.join(__dirname, "userData.db");
let db = null;

const initializeDbAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(4000, () => {
      console.log("Listening to port 4000");
    });
  } catch (error) {
    console.log(`DB Error: ${error.message}`);
    process.exit(1); // Exit the process if the database connection fails
  }
};

initializeDbAndServer();

app.post("/register/", async (request, response) => {
  const { username, name, password, gender, location } = request.body;
  try {
    const checkUserQuery = `SELECT * FROM user WHERE username = ?`;
    const dbResponse = await db.get(checkUserQuery, [username]);

    if (dbResponse) {
      response.status(400).send("User already exists");
    } else if (password.length < 5) {
      response.status(400).send("Password is too short");
    } else {
      const hashedPassword = await bcrypt.hash(password, 10);
      const registerUserQuery = `
        INSERT INTO user (username, name, password, gender, location) 
        VALUES (?, ?, ?, ?, ?)`;
      await db.run(registerUserQuery, [
        username,
        name,
        hashedPassword,
        gender,
        location,
      ]);
      response.send("User created successfully");
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    response.status(500).send("Internal Server Error");
  }
});

app.post("/login/", async (request, response) => {
  const { username, password } = request.body;
  try {
    const checkUserQuery = `SELECT * FROM user WHERE username = ?`;
    const dbResponse = await db.get(checkUserQuery, [username]);

    if (dbResponse === undefined) {
      response.status(400).send("Invalid user");
    } else {
      const isCorrectPassword = await bcrypt.compare(
        password,
        dbResponse.password
      );
      if (isCorrectPassword === false) {
        response.status(400).send("Invalid password");
      } else {
        response.status(200).send("Login success!");
      }
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    response.status(500).send("Internal Server Error");
  }
});

app.put("/change-password/", async (request, response) => {
  const { username, oldPassword, newPassword } = request.body;
  try {
    const checkUserQuery = `SELECT * FROM user WHERE username = ?`;
    const dbResponse = await db.get(checkUserQuery, [username]);

    if (newPassword === dbResponse.password) {
      response.status(400).send("Invalid current password");
    } else if (newPassword.length < 5) {
      response.status(400).send("Password is too short");
    } else {
      let updatePasswordQuery = `
      UPDATE user
      SET
          password = ?
      WHERE username = ?`;
      await db.run(updatePasswordQuery, [newPassword, username]);
      response.status(200).send("Password updated");
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    response.status(500).send("Internal Server Error");
  }
});
