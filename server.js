require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;
const crypto = require("crypto");

const app = express();

app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

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
      error: "Agent API-key is ongeldig of ontbreekt"
    });
  }

  next();
}

function checkDigitaleHandtekening(req, res, next) {
  const agentId = req.headers["x-agent-id"];
  const timestamp = req.headers["x-timestamp"];
  const signature = req.headers["x-signature"];

  if (!agentId || !timestamp || !signature) {
    return res.status(401).json({
      error: "Digitale handtekening ontbreekt"
    });
  }

  const tijdNu = Date.now();
  const tijdRequest = Number(timestamp);
  const verschil = Math.abs(tijdNu - tijdRequest);

  if (verschil > 5 * 60 * 1000) {
    return res.status(401).json({
      error: "Request is te oud"
    });
  }

  const publicKey = process.env.AGENT_PUBLIC_KEY.replace(/\\n/g, "\n");

  const bericht = `${timestamp}.${req.rawBody}`;

  const isGeldig = crypto.verify(
    "sha256",
    Buffer.from(bericht),
    publicKey,
    Buffer.from(signature, "base64")
  );

  if (!isGeldig) {
    return res.status(401).json({
      error: "Digitale handtekening is ongeldig"
    });
  }

  req.agentId = agentId;
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

    <p>Agents kunnen data posten naar <code>/api/agent-data</code>.</p>
    <p>Daarvoor is een API-key én digitale handtekening nodig.</p>
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

    <a href="/medewerkers/pagina2">Ga naar beveiligde pagina 2</a><br>
    <a href="/logout">Uitloggen</a>
  `);
});

app.get("/medewerkers/pagina2", isIngelogd, (req, res) => {
  res.send(`
    <h1>Medewerkerspagina 2</h1>
    <p>Ook deze pagina is beveiligd.</p>

    <a href="/medewerkers">Terug naar pagina 1</a><br>
    <a href="/logout">Uitloggen</a>
  `);
});

app.post(
  "/api/agent-data",
  checkAgentApiKey,
  checkDigitaleHandtekening,
  (req, res) => {
    const data = req.body;

    console.log("Data ontvangen van agent:", req.agentId, data);

    res.json({
      message: "Data veilig ontvangen van agent",
      agent: req.agentId,
      beveiliging: "API-key en digitale handtekening gecontroleerd",
      received: data
    });
  }
);

app.get("/api/agent-data", (req, res) => {
  res.status(405).json({
    error: "Gebruik POST met API-key en digitale handtekening"
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