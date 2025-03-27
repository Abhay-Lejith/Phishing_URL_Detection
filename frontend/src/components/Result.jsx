import React from "react";
import "./Result.css";

const Result = ({ result }) => {
  if (!result) return null;
  if (result.nourl) return <p className="error">{result.nourl}</p>;
  if(result.notvalid) return <p className = "Not a valid url">{result.notvalid}</p>
  return (
    <div className={`result-card ${result.is_malicious ? "phishing" : "safe"}`}>
      <h2>Result:</h2>
      <p>
        This URL is <strong>{result.is_malicious ? "a phishing website." : "safe."}</strong>
      </p>
      <p>Confidence: {Math.round(result.confidence * 100)}%</p>
    </div>
  );
};

export default Result;
