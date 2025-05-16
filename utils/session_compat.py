"""
Flask Session Compatibility Module for Flask 3.x

This module provides a custom session interface that helps manage compatibility issues
between newer Flask versions and older Werkzeug versions, particularly around cookie settings.
"""
from flask.sessions import SecureCookieSessionInterface

class CompatibleSessionInterface(SecureCookieSessionInterface):
    """
    Custom session interface that handles compatibility issues with 'partitioned'
    cookie parameter in newer Flask versions with older Werkzeug versions.
    """
    def save_session(self, app, session, response):
        """
        Save the session in a compatible way by calling the parent implementation
        with a monkey patch to prevent 'partitioned' parameter being used.
        """
        # Original implementation from parent class, but without 'partitioned' parameter
        if not session:
            if session.modified:
                response.delete_cookie(
                    app.session_cookie_name,
                    domain=self.get_cookie_domain(app),
                    path=self.get_cookie_path(app),
                )
            return
        
        # Call the parent implementation but catch and handle any TypeError related to 'partitioned'
        try:
            return super().save_session(app, session, response)
        except TypeError as e:
            if "unexpected keyword argument 'partitioned'" in str(e):
                # If error is about 'partitioned', set cookie manually without that parameter
                if session.modified:
                    domain = self.get_cookie_domain(app)
                    path = self.get_cookie_path(app)
                    
                    response.set_cookie(
                        app.session_cookie_name,
                        self.get_signing_serializer(app).dumps(dict(session)),
                        expires=self.get_expiration_time(app, session),
                        httponly=self.get_cookie_httponly(app),
                        domain=domain,
                        path=path,
                        secure=self.get_cookie_secure(app),
                        samesite=self.get_cookie_samesite(app)
                    )
            else:
                # If it's another TypeError, re-raise it
                raise