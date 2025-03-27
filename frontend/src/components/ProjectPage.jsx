// ProjectPage.js
import React from "react";
import { useNavigate } from 'react-router-dom';
import './ProjectPage.css';
import Header from "./Header";

const ProjectPage = () => {
    const navigate = useNavigate();
    return (
        <div className="container">
           
            <Header/>
            <div className="button-container">
                <button className="button" onClick={() => navigate('/input')}>Press here to Enter Input</button>
            </div>
        </div>
    );
};

export default ProjectPage;
