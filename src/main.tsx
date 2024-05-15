import { render } from "preact";
import { App } from "./app.tsx";
import "./index.css";

if (window.location.pathname && window.location.pathname !== "/") {
  window.location.href = `https://found.as${window.location.pathname}`;
} else {
  render(<App />, document.getElementById("app")!);
}
