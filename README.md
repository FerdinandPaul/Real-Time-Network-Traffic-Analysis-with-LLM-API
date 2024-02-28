
## Project Description: 
Real-Time Network Traffic Analysis with Large Language Model (LLM) API
(This project was conducted solely within my personal network environment to adhere to strict ethical standards and ensure privacy.)

## Project Overview:
This project showcases the innovative use of Large Language Models (LLMs) to analyze and categorize network traffic in real-time. By integrating an LLM API, such as OpenAI's, it captures every DNS query within the network and categorizes the corresponding domain based on its name. The aim is to explore the feasibility and potential benefits of using LLMs for network traffic assessment, starting with domain categorization as an initial step towards more comprehensive analysis capabilities.

## CSV Data Structure and Column Description:
The captured and analyzed data are stored in a CSV file that includes the following columns:

### Timestamp: 
The precise moment the DNS query was captured, formatted as date and time. This information is crucial for tracking activity over time.
### Queried Domain: 
The full domain name that was queried. This forms the basis for categorization and further analysis.
### Device IP: 
The IP address of the device from which the query originated. This can be used to identify patterns or specific devices within the network.
### Source MAC: 
The MAC address of the querying device. Provides an additional layer of identification at the hardware level.
### Destination IP: 
The IP address to which the DNS query was sent, often representing the DNS server.
### Destination MAC: 
The MAC address of the query's target, typically the DNS server.
### Protocol: 
The protocol over which the query was sent (e.g., UDP or TCP), relevant for network traffic analysis.
### Packet Size: 
The size of the network packet in bytes. This can offer insights into the nature of the request and the data transmitted.
### DNS Response Code: 
The response code from the DNS server to the query, shedding light on the success or possible errors.
### Category: 
The category of the queried domain as determined by the LLM, based on the domain name. This provides insights into the types of services being accessed.
Query Count: A count of how often a specific domain was queried within a capture period. This can help identify trends or notable patterns of behavior.

### Example Application (Anonymized)
An anonymized example from the captured data might look as follows:

**Timestamp**: 2024-02-28 08:56:44
**Queried Domain**: ExampleDomain.com
**Device IP**: 192.0.2.1 (Example IP)
**Source/Destination MAC/IP**: Anonymized
**Protocol**: UDP
**Packet Size**: 96 Bytes
**DNS Response Code**: Success
**Category**: Education
**Query Count**: 1

These data illustrate how a DNS query is captured, categorized, and prepared for analysis in real-time without revealing sensitive information.

Conclusion:
This project highlights the potential of LLMs to enhance network security and analysis. By categorizing network traffic in real-time, network administrators and security experts can gain valuable insights to better understand and manage data traffic. The anonymized presentation of the results demonstrates how this technology can be deployed to gain insights into network usage without compromising privacy or security.



