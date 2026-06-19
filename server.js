require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;

const app = express();

app.use(express.json());

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production"
  }
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new GitHubStrategy({
  clientID: process.env.GITHUB_CLIENT_ID,
  clientSecret: process.env.GITHUB_CLIENT_SECRET,
  callbackURL: process.env.CALLBACK_URL
}, function(accessToken, refreshToken, profile, done) {
  return done(null, profile);
}));

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

function isIngelogd(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }

  res.redirect("/");
}

function checkAgentApiKey(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey || apiKey !== process.env.AGENT_API_KEY) {
    return res.status(401).json({
      error: "Agent is niet geautoriseerd"
    });
  }

  next();
}

app.get("/", (req, res) => {
  res.send(`
    <h1>Welkom op de website</h1>
    <p>Dit is het openbare gedeelte van de website.</p>

    <a href="/auth/github">
      <button>Inloggen voor medewerkers</button>
    </a>

    <hr>

    <p>Agents kunnen data posten naar <code>/api/agent-data</code>, maar alleen met een geldige API-key.</p>
  `);
});

app.get("/auth/github",
  passport.authenticate("github", { scope: ["user:email"] })
);

app.get("/auth/github/callback",
  passport.authenticate("github", {
    failureRedirect: "/"
  }),
  (req, res) => {
    res.redirect("/medewerkers");
  }
);

app.get("/medewerkers", isIngelogd, (req, res) => {
  res.send(`
    <h1>Medewerkerspagina 1</h1>
    <p>Welkom, ${req.user.username}.</p>
    <p>Deze pagina is beveiligd met GitHub OAuth 2.0.</p>

    <ul>
      <li>Alleen ingelogde medewerkers kunnen deze pagina bekijken.</li>
      <li>De login verloopt via OAuth 2.0.</li>
      <li>De sessie wordt op de server gecontroleerd.</li>
    </ul>

    <a href="/medewerkers/pagina2">Ga naar beveiligde pagina 2</a><br>
    <a href="/logout">Uitloggen</a>
  `);
});

app.get("/medewerkers/pagina2", isIngelogd, (req, res) => {
  res.send(`
    <h1>Medewerkerspagina 2</h1>
    <p>Ook deze pagina is beveiligd.</p>
    <p>Je kunt deze pagina alleen bereiken als je bent ingelogd.</p>

    <a href="/medewerkers">Terug naar pagina 1</a><br>
    <a href="/logout">Uitloggen</a>
  `);
});

app.post("/api/agent-data", checkAgentApiKey, (req, res) => {
  const data = req.body;

  console.log("Data ontvangen van agent:", data);

  res.json({
    message: "Data veilig ontvangen van agent",
    beveiliging: "API-key gecontroleerd",
    received: data
  });
});

app.get("/api/agent-data", (req, res) => {
  res.status(405).json({
    error: "Gebruik POST met een geldige X-API-Key header"
  });
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Website draait op poort ${PORT}`);
});