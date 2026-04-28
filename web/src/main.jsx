import React from "react";
import { createRoot } from "react-dom/client";
import App from "./App.jsx";
import "./styles.css";

class RuntimeErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <main className="boot-fallback">
          <section>
            <p>CI/CD Security Lab</p>
            <h1>Dashboard error</h1>
            <span>{this.state.error.message || "The dashboard could not render."}</span>
          </section>
        </main>
      );
    }

    return this.props.children;
  }
}

createRoot(document.getElementById("root")).render(
  <RuntimeErrorBoundary>
    <React.StrictMode>
      <App />
    </React.StrictMode>
  </RuntimeErrorBoundary>
);
