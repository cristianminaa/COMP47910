import React from 'react';

const Navbar = ({ userRole, isAuthenticated, csrfToken }) => {
  return (
    <nav className="navbar">
      <div className="navbar-container">
        <a className="navbar-logo" href="/books">Bookshop</a>
        <div className="navbar-actions">
          {userRole === 'ADMIN' && (
            <>
              <div>
                <form action="/new" method="get">
                  <button className="navbar-button" type="submit">Add Book</button>
                </form>
              </div>
              <div>
                <form action="/addAuthor" method="get">
                  <button className="navbar-button" type="submit">Add Author</button>
                </form>
              </div>
            </>
          )}
          {userRole === 'USER' && (
            <form action="/cart" method="get">
              <button className="navbar-button" type="submit">Cart</button>
            </form>
          )}
          {isAuthenticated && (
            <form action="/account" method="get">
              <button className="navbar-button" type="submit">Account</button>
            </form>
          )}
          {isAuthenticated ? (
            <form action="/logout" method="post">
              <input type="hidden" name="_csrf" value={csrfToken} />
              <button className="navbar-button" type="submit">Log out</button>
            </form>
          ) : (
            <form action="/" method="get">
              <button className="navbar-button" type="submit">Log in</button>
            </form>
          )}
        </div>
      </div>
    </nav>
  );
};

export default Navbar;