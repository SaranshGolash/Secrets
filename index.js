import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.set("view engine", "ejs");
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", async (req, res) => {
  res.render("home.ejs");
});

app.get("/login", async (req, res) => {
  res.render("login.ejs");
});

app.get("/register", async (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", async (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.get("/secrets", async (req, res) => {
  console.log("=== SECRETS ROUTE DEBUG ===");
  console.log("req.isAuthenticated():", req.isAuthenticated());
  console.log("req.user:", req.user);
  console.log("req.session:", req.session);
  console.log("========================");
  
  if (req.isAuthenticated()) {
    try {
      const result = await db.query("SELECT secret FROM users WHERE username = $1", [req.user.email]);
      console.log("Database result:", result);
      const secret = result.rows[0]?.secret;
      if(secret) {
        res.render("secrets.ejs", {secret: secret});
      } else {
        res.render("secrets.ejs", {secret: "You should submit a secret"});
      }
    } catch(err) {
      console.log("Database error:", err);
      res.status(500).send("Database error");
    }
  } else {
    console.log("User not authenticated, redirecting to login");
    res.redirect("/login");
  }
});

app.get("/submit", async (req, res) =>{
  if(req.isAuthenticated()){
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  (req, res, next) => {
    console.log("=== LOGIN ATTEMPT ===");
    console.log("Username:", req.body.username);
    console.log("Password received:", !!req.body.password);
    next();
  },
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;
  
  console.log("=== REGISTER ATTEMPT ===");
  console.log("Email:", email);

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE username = $1", [email]);

    if (checkResult.rows.length > 0) {
      console.log("User already exists, redirecting to login");
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.log("Error logging in after registration:", err);
            } else {
              console.log("Registration successful, redirecting to secrets");
              res.redirect("/secrets");
            }
          });
        }
      });
    }
  } catch (err) {
    console.log("Registration error:", err);
  }
});

app.post("/submit", async (req, res) => {
  const secret = req.body.secret;
  console.log(req.user);
  try {
    await db.query("UPDATE users SET secret = $1 WHERE username = $2", [secret, req.user.email]);
    res.redirect("/secrets");
  } catch(err) {
    console.log(err);
  }
})

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    console.log("=== PASSPORT LOCAL STRATEGY ===");
    console.log("Attempting login for username:", username);
    
    try {
      const result = await db.query("SELECT * FROM users WHERE username = $1", [username]);
      console.log("Database query result:", result.rows.length, "users found");
      
      if (result.rows.length > 0) {
        const user = result.rows[0];
        console.log("User found:", { id: user.id, username: user.username });
        const storedHashedPassword = user.password;
        
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            console.log("Password comparison result:", valid);
            if (valid) {
              console.log("Login successful for user:", username);
              return cb(null, user);
            } else {
              console.log("Password invalid for user:", username);
              return cb(null, false);
            }
          }
        });
      } else {
        console.log("No user found with username:", username);
        return cb(null, false);
      }
    } catch (err) {
      console.log("Database error in passport strategy:", err);
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        console.log(profile);
        const result = await db.query("SELECT * FROM users WHERE username = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (username, password) VALUES ($1, $2)",
            [profile.email, "google"]
          );
          return cb(null, newUser.rows[0]);
        } else {
          return cb(null, result.rows[0]);
        }
      } catch (err) {
        return cb(err);
      }
    }
  )
);
passport.serializeUser((user, cb) => {
  console.log("=== SERIALIZE USER ===");
  console.log("Serializing user:", { id: user.id, username: user.username });
  cb(null, user);
});

passport.deserializeUser((user, cb) => {
  console.log("=== DESERIALIZE USER ===");
  console.log("Deserializing user:", { id: user?.id, username: user?.username });
  cb(null, user);
});


app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});