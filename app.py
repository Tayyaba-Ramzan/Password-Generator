import streamlit as st
import random
import string
import math
import pyperclip

# Set page config with favicon
st.set_page_config(
    page_title="Advanced Password Checker", 
    page_icon="🔒", 
    layout="wide", 
    initial_sidebar_state="expanded"
)

# Function to calculate entropy
def calculate_entropy(password):
    character_set = 0
    if any(c.islower() for c in password):
        character_set += 26
    if any(c.isupper() for c in password):
        character_set += 26
    if any(c.isdigit() for c in password):
        character_set += 10
    if any(c in string.punctuation for c in password):
        character_set += len(string.punctuation)
    
    entropy = len(password) * math.log2(character_set) if character_set > 0 else 0
    return entropy

# Function to check password strength
def check_password_strength(password):
    strength = 0
    suggestions = []
    
    if len(password) >= 12:
        strength += 1
    else:
        suggestions.append("Password should be at least 12 characters long.")
    
    if any(char.isupper() for char in password):
        strength += 1
    else:
        suggestions.append("Include at least one uppercase letter.")
    
    if any(char.isdigit() for char in password):
        strength += 1
    else:
        suggestions.append("Include at least one number.")
    
    if any(char in string.punctuation for char in password):
        strength += 1
    else:
        suggestions.append("Include at least one special character.")
    
    entropy = calculate_entropy(password)
    
    return strength, suggestions, entropy

# Function to generate a random password
def generate_password(length, uppercase, numbers, special_chars):
    characters = string.ascii_lowercase
    if uppercase:
        characters += string.ascii_uppercase
    if numbers:
        characters += string.digits
    if special_chars:
        characters += string.punctuation
    
    return ''.join(random.choice(characters) for _ in range(length))

# UI Header
st.title("🔐 Advanced Secure Password Generator")

# Password Strength Checker
st.subheader("🔍 Password Strength Checker")
password = st.text_input("Enter your password", type="password")
show_password = st.checkbox("Show Password")
if show_password:
    st.text_input("Your Password:", password, type="default")

if password:
    strength, suggestions, entropy = check_password_strength(password)
    st.progress(strength / 4)
    
    if strength == 4:
        st.success("✅ Strong Password! Secure against brute-force attacks.")
    elif strength == 3:
        st.warning("⚠️ Moderate Password. Improve security with more complexity.")
    else:
        st.error("❌ Weak Password! Consider the following suggestions:")
        for suggestion in suggestions:
            st.markdown(f"- {suggestion}")
    
    st.metric(label="🔢 Password Entropy", value=f"{entropy:.2f} bits")
    if entropy < 50:
        st.error("⚠️ Password is weak against brute-force attacks!")
    elif entropy < 80:
        st.warning("⚠️ Consider using a longer, more complex password!")
    else:
        st.success("✅ Password is strong against brute-force attacks!")

# Advanced Password Generator
st.subheader("🔑 Secure Password Generator")
length = st.slider("Select Password Length", 8, 30, 16)
st.markdown(f"**Selected Length:** `{length}` characters")

uppercase = st.checkbox("Include Uppercase Letters?")
numbers = st.checkbox("Include Numbers?")
special_chars = st.checkbox("Include Special Characters?")

if st.button("Generate Password"):
    generated_password = generate_password(length, uppercase, numbers, special_chars)
    st.text_area("Generated Password:", generated_password, height=70)
    
    if st.button("Copy to Clipboard"):
        pyperclip.copy(generated_password)
        st.success("📋 Password copied successfully!")

# Sidebar Security Tips
st.sidebar.subheader("📌 Password Security Tips")
st.sidebar.write("✅ Use a mix of uppercase, lowercase, numbers, and special characters.")
st.sidebar.write("✅ Avoid common passwords (e.g., 'password123', '123456').")
st.sidebar.write("✅ Never reuse passwords across multiple accounts.")
st.sidebar.write("✅ Consider using a password manager for secure storage.")
st.sidebar.write("✅ Change passwords regularly for better security.")

# Footer
st.markdown("---")
st.markdown("👨‍💻 Developed by **Tayyaba Ramzan** | 🔐 Secure Your Digital Life 🚀")