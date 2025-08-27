import React from 'react';
import ReactDOM from 'react-dom/client';
import Navbar from './components/Navbar';
import Footer from './components/Footer';

// Initialize components when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
  // Render Navbar
  const navbarElement = document.getElementById('navbar-root');
  if (navbarElement) {
    const navbarProps = {
      userRole: navbarElement.dataset.userRole,
      isAuthenticated: navbarElement.dataset.isAuthenticated === 'true',
      csrfToken: navbarElement.dataset.csrfToken
    };
    
    const navbarRoot = ReactDOM.createRoot(navbarElement);
    navbarRoot.render(<Navbar {...navbarProps} />);
  }

  // Render Footer
  const footerElement = document.getElementById('footer-root');
  if (footerElement) {
    const footerRoot = ReactDOM.createRoot(footerElement);
    footerRoot.render(<Footer />);
  }
});