// ProjectPage.js
import React from "react";
import { useNavigate } from 'react-router-dom';
import './Header.css';

const Header = () => {
    return (
            <div className="content">
                <p className="title">DEPARTMENT OF INFORMATION TECHNOLOGY</p>
                <p className="subtitle">NATIONAL INSTITUTE OF TECHNOLOGY KARNATAKA, SURATHKAL-575025</p>
                
                <p className="text">Information Assurance and Security (IT352) Course Project</p>
                <p className="text">Title: "URL Phishing Detection Using ResMLP"</p>
                
                <p className="text">Carried out by</p>
                <p className="names">Abhay Lejith (221IT002)</p>
                <p className="names">Abhijeet Adi (221IT003)</p>
                <p className="text">During Academic Session January – April 2025</p>
            </div>
    );
};

export default Header;