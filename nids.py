from scapy.all import sniff, IP
from scapy.layers.inet import TCP, UDP
import logging
import pandas as pd
import matplotlib.pyplot as plt

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Function to capture packets
def capture_packets(interface):
    try:
        # Capture 1000 packets from the specified interface
        packets = sniff(iface=interface, count=1000)
        logger.info(f"Captured {len(packets)} packets.")
        return packets 
    except Exception as e:
        logger.error(f"Error capturing packets: {e}")
        return []

# Function to extract features from packets
def extract_features(packets):
    features = []
    for packet in packets:
        try:
            # Extract source and destination IP and port information
            src_ip = packet[IP].src if IP in packet else None
            dst_ip = packet[IP].dst if IP in packet else None
            src_port = packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else None
            dst_port = packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else None

            # Add packet details to the features list
            features.append({
                'source_ip': src_ip,
                'destination_ip': dst_ip,
                'source_port': src_port,
                'destination_port': dst_port,
                'protocol': packet.proto if IP in packet else None
            })

        except AttributeError as attr_err:
            logger.warning(f"Attribute error: {attr_err} in packet {packet.summary()}")
        except Exception as ex:
            logger.error(f"Error extracting features: {ex}")

    return features

# Function to print and display features as a formatted visual report
def generate_visual_report(features):
    # Convert the features list to a DataFrame
    df = pd.DataFrame(features)

    # Display the first few rows of the dataframe
    print("\nSummary of Capture Packets:")
    print(df.head())

    # Check if DataFrame has required columns before plotting
    if 'source_ip' in df.columns:
        generate_bar_chart(df, 'source_ip', 'Packet Distribution by Source IP')
    else: 
        logger.warning("No data available for Source IP column.")

    if 'protocol' in df.columns:
        generate_bar_chart(df, 'protocol', 'Packet Distribution by Protocol')
    else:
        logger.warning("No data available for Protocol column.")

def generate_bar_chart(dataframe, column, title):
    # Count occurrences of each value in the specified column
    value_counts = dataframe[column].value_counts().dropna()

    # Plot the bar chart if there are any values
    if not value_counts.empty:
        plt.figure(figsize=(10,5))
        value_counts.plot(kind='bar')
        plt.title(title)
        plt.xlabel(column)
        plt.ylabel('Number of Packets')
        plt.xticks(rotation=45)
        plt.grid(axis='y', linestyle='--', alpha=0.6)
        plt.tight_layout()
        plt.show()
    else:
        logger.warning(f"No data to plot for {title}.")

# Main function
def main():
    # Specify the network interface
    interface = input("Enter the network interface to capture packets (e.g., Wi-Fi, Ethernet): ")

    # Capture packets on the specified interface
    packets = capture_packets(interface)

    # Extract features from captured packets
    features = extract_features(packets)

    # Print extracted features
    generate_visual_report(features)

if __name__ == "__main__":
    main()