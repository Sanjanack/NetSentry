import streamlit as st
import streamlit_authenticator as stauth
import yaml
from yaml.loader import SafeLoader
import os
import hashlib

def init_auth():
    """Initialize authentication configuration."""
    if not os.path.exists('config.yaml'):
        # Create default config with hashed password
        hashed_password = stauth.Hasher(['admin123']).generate()[0]
        config = {
            'credentials': {
                'usernames': {
                    'admin': {
                        'email': 'admin@example.com',
                        'name': 'Admin User',
                        'password': hashed_password
                    }
                }
            },
            'cookie': {
                'expiry_days': 0,  # Set to 0 to prevent auto-login
                'key': 'netsentry_key',
                'name': 'netsentry_cookie'
            }
        }
        with open('config.yaml', 'w') as file:
            yaml.dump(config, file, default_flow_style=False)

    with open('config.yaml') as file:
        config = yaml.load(file, Loader=SafeLoader)

    # Clear any existing authentication
    if 'authentication_status' in st.session_state:
        del st.session_state['authentication_status']
    if 'name' in st.session_state:
        del st.session_state['name']
    if 'username' in st.session_state:
        del st.session_state['username']

    authenticator = stauth.Authenticate(
        config['credentials'],
        config['cookie']['name'],
        config['cookie']['key'],
        config['cookie']['expiry_days'],
        preauthorized=None  # Disable preauthorized users
    )

    return authenticator

def login():
    """Handle login and return authentication status."""
    try:
        # Initialize the authenticator
        authenticator = init_auth()
        
        # Get login credentials
        name, authentication_status, username = authenticator.login(
            fields={
                'Form name': 'Login',
                'Username': 'Username',
                'Password': 'Password',
                'Submit': 'Login'
            },
            location='main'
        )
        
        if authentication_status == False:
            st.error('Username/password is incorrect')
            st.session_state.authenticated = False
            return False
        elif authentication_status == None:
            st.warning('Please enter your username and password')
            st.session_state.authenticated = False
            return False
        elif authentication_status:
            st.success(f'Welcome *{name}*')
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.name = name
            return True
    except Exception as e:
        st.error(f"Authentication error: {str(e)}")
        st.session_state.authenticated = False
        return False

def logout():
    """Handle user logout."""
    try:
        authenticator = init_auth()
        authenticator.logout('Logout', 'main')
        # Clear authentication state
        st.session_state.authenticated = False
        st.session_state.show_login = False
        if 'username' in st.session_state:
            del st.session_state.username
        if 'name' in st.session_state:
            del st.session_state.name
        st.experimental_rerun()
    except Exception as e:
        st.error(f"Logout error: {str(e)}") 