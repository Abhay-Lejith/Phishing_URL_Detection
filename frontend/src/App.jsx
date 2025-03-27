import React, { useState } from "react";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import InputForm from "./components/InputForm";
import Result from "./components/Result";
import InputPage from "./components/InputPage";
import ProjectPage from "./components/ProjectPage";
import "./App.css";

const App = () => {
  const [result, setResult] = useState(null);

  return (
    <Router>
    <Routes>
      <Route path="/" element={<ProjectPage />} />
      <Route path="/input" element={<InputPage />} />
      <Route path="/input/single" element={<InputForm />} />
    </Routes>
    </Router>
  );
};

export default App;
