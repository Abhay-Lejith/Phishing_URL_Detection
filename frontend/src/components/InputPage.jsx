import React, { useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import Header from "./Header";
import axios from "axios";
import './InputPage.css'

const InputPage = () => {
    const navigate = useNavigate();
    const fileInputRef = useRef(null);
    const [loading, setLoading] = useState(false);

    // Function to trigger file selection
    const handleButtonClick = () => {
        fileInputRef.current.click();
    };

    // Function to handle file selection and process it
    const handleFileUpload = async (event) => {
        const file = event.target.files[0];
        if (!file) return;

        setLoading(true);

        const formData = new FormData();
        formData.append("file", file);

        try {
            const response = await axios.post("http://127.0.0.1:5000/predict_batch", formData, {
                headers: { "Content-Type": "multipart/form-data" },
            });

            const predictions = response.data.predictions.map(
                (item) => `${item.url} - ${item.is_malicious ? "Phishing" : "Safe"} (Confidence: ${item.confidence})`
            );

            downloadOutput(predictions);
        } catch (error) {
            console.error("Error processing file:", error);
            alert("Failed to process file.");
        }

        setLoading(false);
    };

    // Function to download the predictions as a text file
    const downloadOutput = (outputData) => {
        const blob = new Blob([outputData.join("\n")], { type: "text/plain" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = "output.txt";
        link.click();
    };

    return (
        <div className="container">
            <Header/>
            <button
                onClick={() => navigate('/input/single')}
                className="button1"
            >
                Press here to Enter Single URL
            </button>

            <button
                onClick={handleButtonClick}
                className="button1"
                disabled={loading}
            >
                {loading ? "Processing..." : "Press here to Select Text File"}
            </button>

            {/* Hidden file input */}
            <input
                type="file"
                accept=".txt"
                ref={fileInputRef}
                style={{ display: "none" }}
                onChange={handleFileUpload}
            />
        </div>
    );
};

export default InputPage;
