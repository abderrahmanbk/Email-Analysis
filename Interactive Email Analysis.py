import imaplib
import email
import re
import requests
from email.header import decode_header
import logging

# Replace here with your email and your app-specific password for Gmail
EMAIL_USER = "your_email@gmail.com"  # Put your email address here
EMAIL_PASS = "your_app_password"  # Put your specific password here

# API keys
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"  # Replace with your VirusTotal API key
URLHAUS_API_KEY = "your_urlhaus_api_key"  # Replace with your URLhaus API key

# Configure the log file
logging.basicConfig(filename='email_analysis.log', level=logging.INFO)

# Connect to the email account via IMAP
def connect_to_email(username, password):
    mail = imaplib.IMAP4_SSL("imap.gmail.com")
    mail.login(username, password)
    mail.select("inbox")
    print("Email connection successful.")
    return mail

# Retrieve unread emails
def get_unread_emails(mail):
    status, messages = mail.search(None, '(UNSEEN)')
    email_ids = messages[0].split()
    email_list = []
    for email_id in email_ids:
        status, msg_data = mail.fetch(email_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                email_list.append(msg)
    return email_list

# Retrieve a specified number of emails
def get_specific_emails(mail, count):
    status, messages = mail.search(None, 'ALL')
    email_ids = messages[0].split()[-count:]  # Take the last 'count' emails
    email_list = []
    for email_id in email_ids:
        status, msg_data = mail.fetch(email_id, '(RFC822)')
        for response_part in msg_data:
            if isinstance(response_part, tuple):
                msg = email.message_from_bytes(response_part[1])
                email_list.append(msg)
    return email_list

# Retrieve the body of the email securely
def get_email_body(email_msg):
    if email_msg.is_multipart():
        for part in email_msg.walk():
            content_type = part.get_content_type()
            if content_type in ["text/plain", "text/html"]:
                return part.get_payload(decode=True).decode(errors='ignore')
    else:
        return email_msg.get_payload(decode=True).decode(errors='ignore')
    return None  # Return None if no body is found

# Decode the subjects and senders
def decode_mime_words(s):
    decoded_words = decode_header(s)
    return ''.join(
        [t.decode(encoding or 'utf-8') if isinstance(t, bytes) else t for t, encoding in decoded_words]
    )

# Analyze URLs with URLhaus
def check_url_with_urlhaus(url):
    api_url = "https://urlhaus-api.abuse.ch/v1/url/"
    data = {'url': url, 'token': URLHAUS_API_KEY}
    response = requests.post(api_url, data=data)
    result = response.json()

    if result.get('query_status') == 'ok':
        logging.info(f"Malicious URL detected with URLhaus: {url}")
        return result
    return None

# Analyze URLs with VirusTotal
def check_url_with_virustotal(url):
    api_url = f"https://www.virustotal.com/api/v3/urls"
    headers = {
        "x-apikey": VIRUSTOTAL_API_KEY
    }
    # Encode the URL in base64
    url_encoded = requests.utils.quote(url)
    response = requests.post(api_url, headers=headers, data={'url': url_encoded})
    return response.json()

# Extract URLs from an email
def extract_urls_from_email(email_content):
    # Use regular expressions to extract URLs
    urls = re.findall(r'(https?://[^\s]+)', email_content)
    return urls

# Function to quarantine emails
def move_email_to_quarantine(mail, email_id):
    try:
        mail.store(email_id, '+X-GM-LABELS', '\\Quarantine')
        logging.info(f"Email {email_id} moved to quarantine.")
    except imaplib.IMAP4.error as e:
        logging.error(f"Error moving email {email_id} to quarantine: {e}")
        print(f"Error moving email {email_id} to quarantine: {e}")

# Generate a report and save it if the email is suspicious
def generate_report(subject, from_, urls):
    if urls:  # Save only if suspicious URLs are found
        report = f"""
        Email analysis report:
        Subject: {subject}
        From: {from_}
        URLs found: {urls}
        """
        logging.info(report)
        with open("suspect_emails.txt", "a") as f:
            f.write(report + "\n")  # Save to a file
        return report
    return None

# Main function
def main():
    mail = connect_to_email(EMAIL_USER, EMAIL_PASS)

    # Count the total number of emails in the inbox
    mail.select("inbox")
    status, messages = mail.search(None, 'ALL')
    total_emails = len(messages[0].split())
    print(f"Total number of emails in the inbox: {total_emails}")

    choice = input("Would you like to (1) analyze unread emails or (2) specify a number of emails to analyze? (1/2): ")

    if choice == '1':
        emails = get_unread_emails(mail)
    elif choice == '2':
        count = int(input("How many emails would you like to analyze?: "))
        emails = get_specific_emails(mail, count)
    else:
        print("Invalid choice.")
        return

    for email_msg in emails:
        email_body = get_email_body(email_msg)
        if email_body is None:
            print(f"No decodable content for the email: {email_msg['Subject']}")
            continue  # Skip to the next email

        subject = decode_mime_words(email_msg["Subject"])
        from_ = decode_mime_words(email_msg.get("From"))

        print(f"Analyzing email: {subject} from {from_}")

        # Analyze URLs in the email
        urls = extract_urls_from_email(email_body)
        print(f"URLs found: {urls}")  # Display the found URLs
        suspicious_urls = []
        for url in urls:
            # First check with URLhaus
            result_urlhaus = check_url_with_urlhaus(url)
            if result_urlhaus:
                suspicious_urls.append(url)
            # Then check with VirusTotal
            result_virustotal = check_url_with_virustotal(url)
            if result_virustotal.get('data', {}).get('attributes', {}).get('last_analysis_stats'):
                stats = result_virustotal['data']['attributes']['last_analysis_stats']
                if stats['malicious'] > 0:
                    suspicious_urls.append(url)

        # If suspicious URLs are found, move the email to quarantine and generate a report
        if suspicious_urls:
            email_id = email_msg['Message-ID']
            move_email_to_quarantine(mail, email_id)
            logging.info(f"Suspicious email analyzed and moved to quarantine: {subject}")

            # Generate a report and save it
            report = generate_report(subject, from_, suspicious_urls)
            if report:
                print(report)

# Execute the main function
if __name__ == "__main__":
    main()
