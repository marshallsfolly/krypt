import "@fontsource-variable/geist";
import "@fontsource-variable/geist-mono";
import "@fontsource-variable/inter-tight";
import "@fontsource-variable/jetbrains-mono";
import "@fontsource-variable/figtree";
import "./generated/themes.css";
import "./styles.css";
import { render } from "solid-js/web";
import "./app/appearance";
import { fitViewport } from "./app/viewport";
import { App } from "./App";
import { startPinning } from "./release/pin";

fitViewport();
void startPinning();

render(() => <App />, document.getElementById("root")!);
