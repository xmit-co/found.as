import { render } from "preact";
import { App } from "./app.tsx";
import { IndieAuthConsent } from "./components/IndieAuthConsent.tsx";
import { lang } from "./i18n";
import "./index.css";

document.documentElement.lang = lang;

// The IndieAuth authorization endpoint (be.found.as/indieauth) is served by this
// same SPA: when a client sends the user here to approve a sign-in, render the
// consent screen instead of the page builder.
const isIndieAuth =
  location.pathname === "/indieauth" &&
  !!new URLSearchParams(location.search).get("client_id");

render(
  isIndieAuth ? <IndieAuthConsent /> : <App />,
  document.getElementById("app")!,
);
