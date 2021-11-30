const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");

app.use(express.json());



let USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$ZkwWGWl2E53SI3CnxEbp7ubM79oGR3wUa.Ijt2F7hHOMqLdVA.kgG",
    isAdmin: true,
  },
];
let INFORMATION = [{
    email: 'admin@email.com',
    info: 'admin info'
}];

let refreshTokens = [];

let requests = [
    { method: "post", path: "/users/register", description: "Register, Required: email, name, password", example: { body: { email: "user@email.com", name: "user", password: "password" } } },
    { method: "post", path: "/users/login", description: "Login, Required: valid email and password", example: { body: { email: "user@email.com", password: "password" } } },
    { method: "post", path: "/users/token", description: "Renew access token, Required: valid refresh token", example: { headers: { token: "\*Refresh Token\*" } } },
    { method: "post", path: "/users/tokenValidate", description: "Access Token Validation, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
    { method: "get", path: "/api/v1/information", description: "Access user's information, Required: valid access token", example: { headers: { Authorization: "Bearer \*Access Token\*" } } },
    { method: "post", path: "/users/logout", description: "Logout, Required: access token", example: { body: { token: "\*Refresh Token\*" } } },
    { method: "get", path: "api/v1/users", description: "Get users DB, Required: Valid access token of admin user", example: { headers: { authorization: "Bearer \*Access Token\*" } } }
  ]
  
app.post("/users/register", async (req, res) => {
  if (USERS.some((user) => user.email === req.body.email)) {
    return res.status(409).json("user already exists");
  }
  const { email, name, password } = req.body;
  const newUser = {
    email,
    name,
    password: await bcrypt.hash(password, 10),
    isAdmin: false,
  };

  USERS.push(newUser);
  INFORMATION.push({
    email,
    info: `${name} info`,
  });

  res.status(201).json({ message: "Register Success" });
});


app.post("/users/login", async (req, res) => {

    if (req.body.email && !USERS.some((user) => user.email === req.body.email)) {       // looking for user with given email
      return res.status(404).json("cannot find user");
    }
    const { email, password } = req.body;
    const demandUser = USERS.find((user) => user.email === email);          // getting the user object
    bcrypt.compare(password, demandUser.password).then((result) => {        
      if (result) {
        const accessToken = jwt.sign({ user: demandUser.name }, "access_Token", {
          expiresIn: "10s",
        });
        const refreshToken = jwt.sign(
          { user: demandUser.name },
          "refresh_Token"
        );
        refreshTokens.push(refreshToken);
        res.status(200).send({
          accessToken,
          refreshToken,
          email,
          name: demandUser.name,
          isAdmin: demandUser.isAdmin,
        });
      } else {
        res.status(403).send("User or Password incorrect");
      }
    });
  });
      
  app.post("/users/tokenValidate", async (req, res) => {
    const authHeader = req.headers.authorization;
    if(!authHeader) {
        res.status(401).send("Access Token Required");
    }
    const accessToken = authHeader && authHeader.split(" ")[1];
    
    jwt.verify(accessToken, "access_Token", (err, result) => {
     
        if(err) {
            res.status(403).send("Invalid Access Token");
        }
        res.status(200).json({valid: true});
    })
  })

  app.get("/api/v1/information", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).send("Access Token Required");
    }
    const accessToken = authHeader && authHeader.split(" ")[1];

    jwt.verify(accessToken, "access_Token", (err, result) => {
      if (err) {
        res.status(403).send("Invalid Access Token");
      }
      const demandUserEmail = USERS.find(
        (user) => user.name === result.user
      ).email;
      const demandInfo = INFORMATION.find(
        (user) => user.email === demandUserEmail
      );
      res.status(200).json(demandInfo);
    });
  });

  app.post("/users/token", async (req, res) => {
    const refreshToken = req.body.token;
    if(!refreshToken) {
        res.status(401).send("Refresh Token Required");
    }
    else if (!refreshTokens.some((refToken) => refToken === refreshToken)) {  // if the refresh token is not valid - not exits in refreshTokens array
        res.status(403).send("Invalid Refresh Token");
      }
    else {
      jwt.verify(refreshToken, "refresh_Token", (err, result) => {
          if(err) {
            res.status(403).send("Invalid Refresh Token");
          }
          const newAccessToken = jwt.sign({ user: result.user }, "access_Token", {
            expiresIn: "10s",
          });
          res.status(200).json({accessToken: newAccessToken})
      })
    }
  });

  app.post("/users/logout", (req, res) => {
    const refreshToken = req.body.token;
    if (!refreshToken) {
      res.status(400).send("Refresh Token Required");
    } else if (!refreshTokens.some((refToken) => refToken === refreshToken)) {
      // if the refresh token is not valid - not exits in refreshTokens array
      res.status(403).send("Invalid Refresh Token");
    } else {
      let newRefreshTokens = refreshTokens.filter(
        (token) => token !== refreshToken
      );
      refreshTokens = newRefreshTokens;
        res.status(200).send("User Logged Out Successfully");
    }
  });
  
  app.get("/api/v1/users", (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      res.status(401).send("Access Token Required");
    } else {
      const accessToken = authHeader && authHeader.split(" ")[1];
      jwt.verify(accessToken, "access_Token", (err, result) => {
        if (err) {
          res.status(403).send("Invalid Access Token");
        } else {
          const demandAdmin = USERS.find((user) => result.user === user.name);
          if (demandAdmin.isAdmin === true) {
            res.status(200).json({ USERS: USERS });
          } else {
            res.status(403).send("Invalid Access Token");
          }
        }
      });
    }
  });

  app.options("/", (req, res) => {
    const authHeader = req.headers.authorization;
    //   res.setHeader({ Allow: "OPTIONS, GET, POST" });
    if (!authHeader) {
      const options = [requests[0], requests[1]];
      res.send({ Allow: options });
    } else {
      const accessToken = authHeader && authHeader.split(" ")[1];
      jwt.verify(accessToken, "access_Token", (err, result) => {
        if (err) {
          const options = [requests[0], requests[1], requests[2]];
          res.send({ Allow: options });
        } else {
          const demandAdmin = USERS.find((user) => result.user === user.name);
          if (demandAdmin.isAdmin === true) {
            res.send({ Allow: requests });
          } else {
            const options = [
              requests[0],
              requests[1],
              requests[2],
              requests[3],
              requests[4],
              requests[5],
            ];
            res.send({ Allow: options });
          }
        }
      });
    }
  });
  


module.exports = app;
