require("dotenv").config();

const express = require("express");
const session = require("express-session");
const passport = require("passport");
const GitHubStrategy = require("passport-github2").Strategy;

const app = express();

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
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

app.get("/", (req, res) => {
  res.send(`
    <h1>Welkom op de website</h1>
    <p>Dit is het openbare gedeelte van de website.</p>

    <a href="/auth/github">
      <button>Inloggen voor medewerkers</button>
    </a>
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
    <p>Ook deze pagina is afgeschermd.</p>
    <p>Alleen ingelogde medewerkers kunnen deze pagina zien.</p>

    <a href="/medewerkers">Terug naar pagina 1</a><br>
    <a href="/logout">Uitloggen</a>
  `);
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