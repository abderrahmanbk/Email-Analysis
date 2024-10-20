import imaplib
import email
import re
import requests
import time
from email.header import decode_header
import logging
import os

# Replace with your Gmail email and application-specific password
EMAIL_USER = "your_email@gmail.com"
EMAIL_PASS = "your_app_password"

# API keys for security services
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
URLHAUS_API_KEY = "your_urlhaus_api_key"

# Configure logging system
logging.basicConfig(filename='email_analysis.log', level=logging.INFO)

# File to store IDs of already analyzed emails
ANALYZED_EMAILS_FILE = "analyzed_emails.txt"

# Check if the file exists, if not create it
if not os.path.exists(ANALYZED_EMAILS_FILE):
    with open(ANALYZED_EMAILS_FILE, 'w') as f:
        pass

# Function to establish a connection to the email account via IMAP
def connect_to_email(username, password):
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(username, password)
    print("Successfully connected to the email.")
    return mail

# Retrieve all unread emails in the inbox
def get_all_emails(mail):
    mail.select("inbox")  # Select the inbox
    status, messages = mail.search(None, 'UNSEEN')  # Search for unread emails only
    email_ids = messages[0].split()  # Get the IDs of unread emails
    email_list = []
    for email_id in email_ids:
        status, msg_data = mail.fetch(email_id, '(RFC822)')  # Fetch the email
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                email_list.append((email_id, msg))  # Return the ID and the message
    return email_list

# Extract the body of the email securely
def get_email_body(email_msg):
    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                return part.get_payload(decode=True).decode(errors='ignore')  # Return the decoded body
    else:
        return email_msg.get_payload(decode=True).decode(errors='ignore')
    return None

# Decode the subjects and senders of emails
def decode_mime_words(s):
    decoded_words = decode_header(s)
    return ''.join(
        [t.decode(encoding or 'utf-8') if isinstance(t, bytes) else t for t, encoding in decoded_words]
    )

# Function to check a URL with the URLhaus API
def check_url_with_urlhaus(url):
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {'url': url, 'token': URLHAUS_API_KEY}
    response = requests.post(api_url, data=data)
    result = response.json()

    if result.get('query_status') == 'ok':
        logging.info(f"Malicious URL detected with URLhaus: {url}")
        return result
    return None

# Function to check a URL with the VirusTotal API
def check_url_with_virustotal(url):
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    url_encoded = requests.utils.quote(url)
    response = requests.post(api_url, headers=headers, data={'url': url_encoded})
    return response.json()

# Extract URLs from an email
def extract_urls_from_email(email_content):
    urls = re.findall(r'(https?://[^\s]+)', email_content)  # Use a regex to find URLs
    return [url.rstrip('>') for url in urls]  # Remove trailing '>' character

# Function to quarantine suspicious emails
def move_email_to_quarantine(mail, email_id):
    try:
        mail.store(email_id, '+X-GM-LABELS', 'Quarantine')  # Move the email to quarantine
        logging.info(f"Email {email_id} moved to quarantine.")
    except imaplib.IMAP4.error as e:
        logging.error(f"Error moving email {email_id} to quarantine: {e}")
        print(f"Error moving email {email_id} to quarantine: {e}")

# Generate a report and save it if the email is suspicious
def generate_report(subject, from_, urls):
    report = f"""
    Email Analysis Report:
    Subject: {subject}
    Sender: {from_}
    Found URLs: {urls}
    """
    logging.info(report)  # Log the report in the log file
    with open("suspect_emails.txt", "a") as f:
        f.write(report + '\n')  # Write the report to a file

# Read IDs of already analyzed emails
def read_analyzed_emails():
    with open(ANALYZED_EMAILS_FILE, 'r') as f:
        return set(line.strip() for line in f)  # Return a set of already analyzed email IDs

# Write a new analyzed email ID to the file
def write_analyzed_email(email_id):
    if isinstance(email_id, bytes):
        email_id = email_id.decode()  # Decode if it's in bytes
    with open(ANALYZED_EMAILS_FILE, 'a') as f:
        f.write(email_id + '\n')  # Write the email ID to the file

# Main function
def main():
    mail = connect_to_email(EMAIL_USER, EMAIL_PASS)  # Establish the connection
    analyzed_emails = read_analyzed_emails()  # Read already analyzed emails

    while True:
        print("Checking emails...")  # Indicate that the checking is starting
        emails = get_all_emails(mail)  # Get all unread emails

        for email_id, email_msg in emails:
            if email_id in analyzed_emails:  # Check if the email has already been analyzed
                print(f"Email already analyzed: {email_id}. Skipping to the next email.")
                continue

            email_body = get_email_body(email_msg)  # Get the email body
            if email_body is None:
                print(f"No decodable content for the email: {email_msg['Subject']}")
                continue

            print(f"Email content: {email_body}")  # Display the email content for debugging

            subject = decode_mime_words(email_msg["Subject"])  # Decode the email subject
            from_ = decode_mime_words(email_msg.get("From"))  # Decode the sender

            print(f"Analyzing email: {subject} from {from_}")

            # Analyze URLs in the email
            urls = extract_urls_from_email(email_body)  # Extract the URLs
            print(f"Found URLs: {urls}")  # Display the found URLs
            suspicious_urls = []  # List to store suspicious URLs

            # Check each URL with URLhaus and VirusTotal
            for url in urls:
                result_urlhaus = check_url_with_urlhaus(url)
                if result_urlhaus:
                    suspicious_urls.append(url)  # Add to the list if URLhaus flags an issue
                result_virustotal = check_url_with_virustotal(url)
                if result_virustotal.get('data', {}).get('attributes', {}).get('last_analysis_stats'):
                    stats = result_virustotal['data']['attributes']['last_analysis_stats']
                    if stats['malicious'] > 0:  # Check if the URL is reported as malicious
                        suspicious_urls.append(url)

            # If suspicious URLs are found, quarantine the email and generate a report
            if suspicious_urls:
                move_email_to_quarantine(mail, email_id)
                logging.info(f"Suspicious email analyzed and moved to quarantine: {subject}")
                generate_report(subject, from_, suspicious_urls)

            write_analyzed_email(email_id)  # Write the analyzed email ID
            analyzed_emails.add(email_id)  # Add to the set of analyzed emails

        # Wait 10 seconds before checking again
        time.sleep(10)

# Run the main function
if __name__ == "__main__":
    main()
