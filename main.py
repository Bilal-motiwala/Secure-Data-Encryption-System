import streamlit as st
import hashlib
from cryptography.fernet import Fernet

# App metadata
st.set_page_config(page_title="Secure Data Vault", layout="centered")

# Title and Styling
st.markdown("""
    <style>
        .main {background-color: #f4f4f9;}
        h1, h2, h3 {color: #4B8BBE; text-align: center;}
        .stButton button {background-color: #4B8BBE; color: white; border-radius: 10px;}
    </style>
""", unsafe_allow_html=True)

st.title("🔒 Secure Data Encryption System")
st.caption("Created by Bilal Motiwala")

# Generate encryption key once
if "fernet_key" not in st.session_state:
    st.session_state.fernet_key = Fernet.generate_key()
    st.session_state.fernet = Fernet(st.session_state.fernet_key)
    st.session_state.data = {}
    st.session_state.attempts = 0
    st.session_state.authorized = True

# Hash function
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Login page
def login_page():
    st.subheader("🔐 Reauthorization Required")
    password = st.text_input("Enter Admin Password", type="password")
    if st.button("Login"):
        if password == "admin123":  # changeable in real-world case
            st.session_state.attempts = 0
            st.session_state.authorized = True
            st.success("Access Granted")
        else:
            st.error("Wrong Password")

# Store data page
def store_data():
    st.subheader("📥 Store New Data")
    username = st.text_input("Enter a unique key (e.g., username)")
    data = st.text_area("Enter your secret data")
    passkey = st.text_input("Set a passkey", type="password")
    if st.button("Encrypt & Store"):
        if username and data and passkey:
            hashed = hash_passkey(passkey)
            encrypted = st.session_state.fernet.encrypt(data.encode()).decode()
            st.session_state.data[username] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            st.success("Data stored securely!")
        else:
            st.warning("Please fill all fields.")

# Retrieve data page
def retrieve_data():
    st.subheader("📤 Retrieve Data")
    username = st.text_input("Enter your key (e.g., username)")
    passkey = st.text_input("Enter your passkey", type="password")
    if st.button("Decrypt"):
        if username in st.session_state.data:
            correct_hash = st.session_state.data[username]["passkey"]
            if hash_passkey(passkey) == correct_hash:
                decrypted = st.session_state.fernet.decrypt(
                    st.session_state.data[username]["encrypted_text"].encode()
                ).decode()
                st.success("Decrypted Data:")
                st.code(decrypted)
                st.session_state.attempts = 0
            else:
                st.session_state.attempts += 1
                st.error(f"Incorrect passkey. Attempts: {st.session_state.attempts}/3")
                if st.session_state.attempts >= 3:
                    st.session_state.authorized = False
        else:
            st.warning("No data found for this key.")

# Navigation
if not st.session_state.authorized:
    login_page()
else:
    page = st.radio("Choose Action", ["Home", "Insert Data", "Retrieve Data"], horizontal=True)

    if page == "Home":
        st.markdown("""
            ## 👋 Welcome to Secure Vault
            Choose an action from above to store or retrieve your data securely.
        """)

    elif page == "Insert Data":
        store_data()

    elif page == "Retrieve Data":
        retrieve_data()
