import psutil
import joblib
import numpy as np
from time import sleep
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Load the trained Meta-CyberIDS model
model = joblib.load('./Meta_CyberIDS.joblib')

# Network interface for monitoring
interface = 'eth0'

# Email alert function
def send_alert(subject, body):
    sender_email = "Alvy.sun@example.com"
    receiver_email = "admin@example.com"
    password = "Alvy.sun"  # Avoid storing passwords in plain text

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    with smtplib.SMTP_SSL('smtp.example.com', 465) as server:
        server.login(sender_email, password)
        server.sendmail(sender_email, receiver_email, msg.as_string())

# Capture network traffic and convert it into a suitable feature format
def get_network_data():
    net_data = psutil.net_io_counters(pernic=True)
    data = net_data[interface]
    return [data.bytes_sent, data.bytes_recv, data.packets_sent, data.packets_recv]

# Intrusion detection loop
def intrusion_detection():
    while True:
        print("Monitoring network traffic...")
        
        # Capture network traffic data
        network_data = get_network_data()
        
        # Transform network data into features expected by the model
        features = np.array(network_data).reshape(1, -1)  # Reshape to 2D array for model input
        
        # Make prediction using the trained model
        prediction = model.predict(features)
        
        # If prediction indicates intrusion, send an alert
        if prediction == 1:
            print("Potential intrusion detected!")
            send_alert("Intrusion Alert", "An intrusion has been detected based on real-time network traffic.")    
        sleep(1)

if __name__ == "__main__":
    intrusion_detection()
