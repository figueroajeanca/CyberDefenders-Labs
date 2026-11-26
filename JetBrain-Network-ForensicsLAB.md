# JetBrains – Network Forensics

**Platform:** CyberDefenders  
**Primary Tool:** Wireshark  
**Category:** Network Forensics  
**Status:** COMPLETED

## 1. Introduction

This lab focuses on analyzing network traffic captured from an environment running a JetBrains TeamCity server.

The objective is to investigate network communications, identify suspicious activity, and collect evidence to reconstruct the actions performed during the incident.

The answers of the questions will be investigated and documented step by step, including the analysis process and supporting evidence. All questions and their corresponding answers will be summarized in a dedicated section at the end of this walkthrough.

## 2. SCENARIO

SCENARIO: During a recent security incident, an attacker successfully exploited a vulnerability in our web server, allowing them to upload webshells and gain full control over the system. The attacker utilized the compromised web server as a launch point for further malicious activities, including data manipulation. 

As part of the investigation, You are provided with a packet capture (PCAP) of the network traffic during the attack to piece together the attack timeline and identify the methods used by the attacker. The goal is to determine the initial entry point, the attacker's tools and techniques, and the compromise's extent.

### 2.1 PCAP File Properties

The investigation began by opening the "Capture.pcap" file in Wireshark to examine the recorded network traffic and identify the capture's general characteristics.

The **Statistics → Capture File Properties** feature was used to inspect the metadata of the capture file.

The following information was collected:

| Property | Value |
|---|---|
| File name | Capture.pcap |
| File size | 25 MB |
| File format | PCAP |
| Encapsulation | Linux cooked-mode capture v2 |
| First packet | 2024-06-30 07:45:15 UTC |
| Last packet | 2024-06-30 08:26:30 UTC |
| Capture duration | 00:41:15 |
| Total packets | 33,279 |
| Average packets per second | 13.4 |
| Captured bytes | 24,698,612 |
| SHA256 | `504b4a8cf895bf44f2dc3cdef3e0e5952e2d89913cd3525258dab40a7648e79c` |

<img width="1282" height="807" alt="Jetbrains 2" src="https://github.com/user-attachments/assets/ff39fb83-d265-433a-8756-2b6221732f64" />

### 2.2 IPv4 Conversations Analysis

After reviewing the PCAP file properties, the IPv4 Conversations feature in Wireshark was used to identify the hosts communicating within the captured network traffic.

This analysis helped identify the most active IP addresses and establish an initial understanding of the network communications.

The capture contained **419 IPv4 conversations**.

<img width="1917" height="842" alt="jetbrains 3" src="https://github.com/user-attachments/assets/81369c46-e8c8-4c63-9e1a-6fb388dd4ab5" />

### 2.3 HTTP Request Analysis

After analyzing the IPv4 conversations, the HTTP traffic was examined using the following Wireshark display filter:

`http.request`

This filter displayed HTTP requests found in the packet capture, allowing us to investigate web activity and identify potentially suspicious communications.

During this analysis, several requests originating from `23.158.56.196` caught our attention.

<img width="1911" height="802" alt="jetbrains 6" src="https://github.com/user-attachments/assets/9869a4a2-e110-49ae-a5cb-aec5ffa50350" />

### 2.4 Identification of Suspicious HTTP Requests

During the HTTP request analysis, several suspicious requests originating from `23.158.56.196` were identified.

Some of the most relevant requests included:

- `GET /hax?jsp=/app/rest/server;.jsp`
- `POST /hax?jsp=/app/rest/users;.jsp`
- `POST /admin/plugins.html`
- `POST /loginSubmit.html`

The requests targeting `/hax` were particularly suspicious because they accessed TeamCity REST API endpoints through an unusual JSP path.

To better understand the activity, the request to `/hax?jsp=/app/rest/server;.jsp` was selected for further investigation using Wireshark's **Follow TCP Stream** feature.

<img width="1022" height="752" alt="image" src="https://github.com/user-attachments/assets/787f187c-6491-4a68-b84c-0f7282f7cde4" />

### 2.4 Attacker IP Identification

After examining the HTTP requests, several suspicious communications originating from `23.158.56.196` were identified.

This IP address appeared repeatedly in requests targeting the internal TeamCity server, including unusual requests to REST API endpoints.

Based on the observed HTTP traffic, `23.158.56.196` was identified as the attacker's IP address.

**Answer question 1:** `23.158.56.196`

### 2.5 TeamCity Version Identification

To identify the version of the web server service, the suspicious HTTP request below was investigated:

`GET /hax?jsp=/app/rest/server;.jsp`

Using Wireshark's **Follow TCP Stream** feature, the complete HTTP communication between the attacker and the TeamCity server was examined.

The server returned an XML response containing the following version information:

`version="2023.11.3 (build 147512)"`

This confirmed that the affected server was running **JetBrains TeamCity 2023.11.3**.

**Answer question 2:** `2023.11.3`

### 2.6 Vulnerability Identification

After identifying the TeamCity version, the next step was to determine which vulnerability could have been exploited.

The server was running TeamCity `2023.11.3`, a version affected by **CVE-2024-27198**, an authentication bypass vulnerability.

The suspicious requests observed in the packet capture were consistent with exploitation of this vulnerability, which allows unauthenticated attackers to bypass authentication and access protected server functionality.

The TCP stream also revealed that the attacker successfully created a user with the `SYSTEM_ADMIN` role and generated an authentication token.

These actions provide evidence of unauthorized administrative access to the TeamCity server.

**Answer question 3:** `CVE-2024-27198`

<img width="1472" height="752" alt="jetbrains 7" src="https://github.com/user-attachments/assets/07bcec93-721e-4664-ab79-680db7da75ba" />

### 2.7 HTTP Basic Authentication Analysis

To identify the credentials used by the attacker, the following Wireshark display filter was applied:

`http.authentication`

This filter displayed packets containing HTTP authentication information.

The first relevant packet identified was **Frame 24728**. After selecting it, the TCP conversation was examined using:

**Follow → TCP Stream**

By inspecting the stream, the `username` and `password` fields were identified.

The credentials found were:

- **Username:** `c91oyemw`
- **Password:** `CL5vzdwLuK`

**Answer question 4:** `c91oyemw / CL5vzdwLuK`

<img width="1896" height="682" alt="jetbrains 8" src="https://github.com/user-attachments/assets/117bcf8b-de10-4f73-9db7-858ab3a68a68" />
<img width="1001" height="196" alt="jetbrains 9" src="https://github.com/user-attachments/assets/a8702c0f-6102-4a9d-8afd-a26fd4c94944" />

### 2.8 Webshell Upload Identification

While examining the same TCP Stream used in the previous question, an HTTP POST request to the following endpoint was identified:

`POST /admin/pluginUpload.html`

The request contained a multipart form-data upload. By inspecting the `Content-Disposition` headers, the uploaded filename was identified:

```http
Content-Disposition: form-data; name="fileName"

NSt8bHTg.zip

Content-Disposition: form-data; name="file:fileToUpload"; filename="NSt8bHTg.zip"
Content-Type: application/zip
```

The uploaded ZIP archive contained the following files:

```text
server/NSt8bHTg.jar
buildServerResources/NSt8bHTg.jsp
teamcity-plugin.xml
```
<img width="1012" height="736" alt="jetbrains 10" src="https://github.com/user-attachments/assets/1afe802d-d29d-4c01-a830-a7553cde16f6" />

Further inspection of `buildServerResources/NSt8bHTg.jsp` revealed code that retrieves a `cmd` request parameter and uses Java's `ProcessBuilder` to execute operating system commands.

This behavior identifies the JSP file as a webshell, allowing the attacker to execute commands on the compromised server through HTTP requests.

The server responded with `HTTP/1.1 200`, indicating that the plugin upload request was accepted.

**Answer question 5:** `NSt8bHTg.zip`
### 2.9 First Command Execution via Webshell

After identifying the uploaded webshell (`NSt8bHTg.jsp`), the next step was to determine when the attacker executed the first command through it.

**Step 1: Locate requests to the webshell**

The following Wireshark display filter was applied:

`http.request.uri contains "NSt8bHTg.jsp"`

This filter displayed HTTP requests targeting the uploaded JSP webshell.

**Step 2: Identify the first request**

The first relevant request identified was **Frame 25572**.

The HTTP request was:

```http
POST /plugins/NSt8bHTg/NSt8bHTg.jsp HTTP/1.1
```

**Step 3: Inspect the HTTP request parameters**

The packet details were expanded in Wireshark to inspect the URL-encoded form data.

The following parameter was identified:

```text
Form item: "cmd" = "ls"
```

This showed that the attacker sent the `ls` command to the webshell.

The `ls` command is used in Linux to list files and directories in the current directory.

**Findings:**

- **Attacker IP:** `23.158.56.196`
- **Packet number:** `25572`
- **Webshell:** `NSt8bHTg.jsp`
- **First command identified:** `ls`
- **Execution date:** June 30, 2024
- **Execution time:** 08:03 (exact seconds to be confirmed from the Wireshark Time column)

**Answer question 6:** 2024-06-30 08:03 

<img width="1112" height="740" alt="jetbrains 11" src="https://github.com/user-attachments/assets/606f7edb-6f09-49e1-9173-e6e9a150d582" />

### 2.10 Attacker Credentials Modification

The next step was to investigate how the attacker manipulated a text file containing administrator credentials through the uploaded webshell.

**Step 1: Filter Webshell Requests**

The following Wireshark display filter was applied to identify HTTP requests sent to the uploaded webshell:

`http.request.uri contains "NSt8bHTg.jsp"`

This allowed us to focus on the attacker's interactions with the webshell.

**Step 2: Identify the Credentials File**

While examining the POST requests, Frame `26895` revealed the following command:

```bash
cat /tmp/Creds.txt
```
<img width="955" height="647" alt="jetbrains 12" src="https://github.com/user-attachments/assets/8f9da878-8100-487e-9beb-1787755ba1bb" />

The `cat` command is used to read the contents of a file. This indicated that the attacker was accessing a file named `Creds.txt` located in the `/tmp` directory.

**Step 3: Identify the Modified Credentials**

Further investigation led to Frame `31123`, which contained the following command:

```bash
bash -c 'echo "username:a1l4m,password:youarecompromised" > /tmp/Creds.txt'
```

This command uses:

- `bash -c`: Executes a command through Bash.
- `echo`: Outputs the specified text.
- `>`: Redirects the output to a file, overwriting its existing contents.
- `/tmp/Creds.txt`: The file where the credentials were written.

**Step 4: Extract the New Credentials**

By analyzing the command in Frame `31123`, the new credentials written to the file were identified:

<img width="1307" height="586" alt="jetbrains 13" src="https://github.com/user-attachments/assets/1846c448-cffe-41f3-9b7f-3384b9e511a6" />

The attacker used the webshell to execute a Bash command that overwrote `/tmp/Creds.txt` with a new username and password.

**Answer question 7:** `a1l4m:youarecompromised`

### 2.11 MITRE ATT&CK – Data Manipulation

After analyzing Frame `31123`, we identified that the attacker overwrote `/tmp/Creds.txt` with false administrator credentials using the `>` redirection operator.

This action corresponds to the following MITRE ATT&CK sub-technique:

- **Technique:** T1565 – Data Manipulation
- **Sub-technique:** T1565.001 – Stored Data Manipulation

**Answer question 8:** `T1565.001`

**Reference:** https://attack.mitre.org/techniques/T1565/001/

<img width="1911" height="755" alt="jetbrains 14" src="https://github.com/user-attachments/assets/116b4b56-5c23-43cd-aa46-89b88067cdf3" />

### 2.12 Docker Command – Host Filesystem Access

**Step 1: Search for the Command**

Applied the following Wireshark display filter:

`http contains "chroot"`

**Step 2: Identify the Request**

Frame `32112` revealed an HTTP POST request from `23.158.56.196` to `172.17.0.2`.

Inside `HTML Form URL Encoded`, the `cmd` parameter contained:

```bash
docker run --rm -it -v /:/host ubuntu chroot /host
```

**Step 3: Command Analysis**

- `docker run`: Starts an Ubuntu container.
- `-v /:/host`: Mounts the host's root filesystem inside the container.
- `chroot /host`: Changes the process root to the mounted host filesystem.

The attacker used `chroot` because Docker alone would keep the process in the container's default filesystem. By mounting the host filesystem and changing the root directory, the attacker could interact directly with the host's files.

**Answer question 9:** `docker run --rm -it -v /:/host ubuntu chroot /host`

<img width="962" height="590" alt="jetbrains 15" src="https://github.com/user-attachments/assets/6a86dac0-f3e1-49ef-a229-ecd2a512be40" />

## 3. Lab Conclusion

Throughout this investigation, I analyzed network traffic in Wireshark to reconstruct an attack against a JetBrains TeamCity server.

The investigation revealed how the attacker exploited a vulnerability, created an administrator account, uploaded a webshell, executed system commands, modified credentials, and used Docker to access the host filesystem.

This lab helped me practice:

- HTTP traffic analysis with Wireshark.
- Identifying suspicious requests and attacker activity.
- Understanding webshells and remote command execution.
- Recognizing credential manipulation.
- Mapping attacker behavior to MITRE ATT&CK.
- Understanding Docker and Linux `chroot` commands.

**Key Takeaway:**

Network traffic analysis is essential for identifying malicious activity, understanding attack techniques, and reconstructing security incidents.

## 4. Lab Questions & Answers

1. **What is the attacker's IP address?**  
   Answer: `23.158.56.196`

2. **What is the version of the TeamCity server?**  
   Answer: `2023.11.3`

3. **What vulnerability was exploited by the attacker?**  
   Answer: `CVE-2024-27198`

4. **What credentials did the attacker use to create an administrator account?**  
   Answer: `c91oyemw:CL5vzdwLuK`

5. **What was the name of the uploaded webshell archive?**  
   Answer: `NSt8bHTg.zip`

6. **When did the attacker execute the first command through the webshell?**  
   Answer: 2024-06-30 08:03

7. **What new username and password did the attacker write into Creds.txt?**  
   Answer: `a1l4m:youarecompromised`

8. **Which MITRE ATT&CK sub-technique describes the file modification?**  
   Answer: `T1565.001`

9. **What Docker command did the attacker execute to mount the host filesystem and use chroot?**  
   Answer: `docker run --rm -it -v /:/host ubuntu chroot /host`

JetBrains Blue Team Lab at CyberDefenders!:
https://cyberdefenders.org/blueteam-ctf-challenges/achievements/jeancafigueroagomez1/jetbrains/
 
