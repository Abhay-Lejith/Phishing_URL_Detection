import React, { useState } from "react";
import axios from "axios";  // ✅ Import axios
import Result from "./Result";
import "./InputForm.css";

const InputForm = () => {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://127.0.0.1:5000/predict", { url });
      setResult(response.data);
    } catch (error) {
      console.error("Error fetching data:", error);
      setResult({ error: "Failed to connect to server" });
    }
  };

  return (
    <div className="container1">
    <p className="title1">Enter a URL :</p>
    <form onSubmit={handleSubmit} className="input-form">
      <input
        type="text"
        placeholder="Enter URL here"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        required
      />
      <button type="submit">Check</button>
    </form>
    <Result result={result} />
    </div>
  );
};

export default InputForm;
