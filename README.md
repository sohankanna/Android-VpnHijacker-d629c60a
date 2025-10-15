# Analysis of Android/Spy.VpnHijacker.A (d629c60a)

**DISCLAIMER:** *This repository contains the analysis of a malicious Android application. The information provided is for educational and research purposes only. Do not attempt to download, run, or replicate this malware on any personal or production device. All analysis was performed in a controlled, isolated virtual environment. The author is not responsible for any damage caused by the misuse of this information.*

***

## 1. Executive Summary

This report details the in-depth analysis of the Android Trojan `SBI AADHAR UPDATE.APK`. The sample was discovered being distributed via a compromised WhatsApp group and uses a multi-layered attack strategy. It is classified as **Android/Spy.VpnHijacker.A** with an integrated phishing module.

The malware's primary functions are twofold:
1.  **Active Credential Theft:** It presents the user with a deceptive installation screen, followed by a convincing phishing page masquerading as an SBI (State Bank of India) login portal to harvest usernames, passwords, and mobile numbers.
2.  **Passive Data Interception:** In the background, it establishes a malicious `VpnService` tunnel, performing a comprehensive Man-in-the-Middle (MitM) attack to intercept all network traffic from the device.

The malware is protected by advanced obfuscation, string encryption, and anti-analysis techniques designed to break standard reverse-engineering tools. Dynamic analysis confirmed the phishing payload but did not reveal an immediate C2 exfiltration channel, strongly suggesting the malware employs anti-sandbox techniques to hide its full network infrastructure.

## 2. Indicators of Compromise (IOCs)

*   **File Name:** `SBI AADHAR UPDATE.APK`
*   **Package Name:** `com.iudxmm.android`
*   **MD5:** `d629c60a87dd3aa83072e1ee5ee56597`
*   **SHA256:** `27051a225ea950c7d62ddbac6c7c4754bf86be94fddf0d3c10e2827d6eedffd5`
*   **C2 Server IP:** `Not Observed (Suspected Anti-Sandbox Evasion)`
*   **C2 Port:** `Not Observed (Suspected Anti-Sandbox Evasion)`

## 3. Attack Vector & Social Engineering

The malware was distributed through a compromised WhatsApp group. The threat actor took control of the group, changed its name and logo to appear official, and then posted a message urging members to download and install the malicious APK under a plausible pretext.

This method is highly effective as it leverages the inherent trust within a known social group to bypass user suspicion.

![Compromised WhatsApp Group](https://github.com/user-attachments/assets/34155e14-a236-4141-b5dc-577dfa5888a3)

## 4. User-Facing Payload: Deception & Credential Phishing

Once the user initiates the installation, the malware begins a multi-stage deception to harvest credentials.

### 4.1. Fake Installation Lure

The malware first displays a fake installation screen impersonating the legitimate "YONO SBI" mobile banking application. This reassures the victim that they are installing a trusted application while the malicious services are prepared in the background.
<img width="873" height="381" alt="Screenshot 2025-10-15 101148" src="https://github.com/user-attachments/assets/50599d87-22f7-45c7-a379-7254505d4e2a" />


### 4.2. Credential Harvesting Page

Immediately after the fake installation, the application displays a WebView containing a phishing page designed to perfectly mimic the SBI Reward Points login portal. The page prompts the user to enter their Username, Password, and Mobile Number. Any credentials entered into this form are captured by the malware and are likely exfiltrated to the C2 server.

<img width="1006" height="491" alt="Screenshot 2025-10-15 101219" src="https://github.com/user-attachments/assets/08eacdf0-4459-462d-be8e-ef35f76bacdd" />

## 5. Static Analysis (Technical Deep Dive)

While the user is being phished, the malware's core technical payload operates in the background.

### 5.1. Initial Triage & Anti-Analysis Techniques

Initial attempts to decompile the APK using `apktool` failed with a `java.util.zip.ZipException: invalid CEN header (bad compression method: 39310)`. This is a deliberate anti-analysis technique where the APK's ZIP header is malformed to crash reverse-engineering tools. The analysis proceeded by loading the sample into JADX.

![JADX Decompiled View](https://github.com/user-attachments/assets/fcd1dee3-bf07-43f1-9dea-9c2d3c9289fd)

Initial string analysis revealed an unusual signature containing Chinese characters, a potential indicator of the toolchain used by the developer.

![Chinese Characters in Strings](https://github.com/user-attachments/assets/d4ec62c2-d2f9-44f5-a9bd-359df5bb6910)

### 5.2. Manifest Analysis

The `AndroidManifest.xml` confirmed the malicious intent by declaring dangerous permissions, including `android.permission.BIND_VPN_SERVICE` (for the VPN payload) and `android.permission.REQUEST_INSTALL_PACKAGES` (for dropper functionality).

### 5.3. Code Obfuscation

The codebase was protected by multiple layers of obfuscation, including identifier renaming, encrypted strings stored in `short[]` arrays, and control-flow flattening.

### 5.4. Core Payload: VPN Hijacking

The malware's passive data interception payload resides in the `run()` method of the `A.a` class, executed as a background thread. The critical instruction **`builder.addRoute("0.0.0.0", 0);`** is invoked, hijacking the device's networking and forcing all traffic from every application into the malware's tunnel for inspection and exfiltration.

![Core VPN Hijacking Code](https://github.com/user-attachments/assets/d0daf02f-f2de-4ba6-9477-ea8ca0386ae4)

## 6. The Hunt for the C2: An Evasion Analysis

A systematic static hunt for the C2 server address revealed a deliberate strategy of misdirection, including the use of a heavily obfuscated legitimate Android library (`MenuInflater`) as a high-confidence decoy to mislead analysts. The failure to find the C2 endpoint via static methods proves the threat actor is using advanced techniques such as JNI or dynamic code loading.

## 7. Dynamic Analysis & Observed Behavior

Due to the limitations of static analysis, the APK was submitted to the Any.Run and Hybrid Analysis online sandboxes to observe its live behavior.

*   **Link to Any.Run Report:** `https://app.any.run/tasks/37cab757-f632-4db1-baef-99002328ed1e`
*   **Link to Hybrid Analysis Report:** `https://hybrid-analysis.com/sample/27051a225ea950c7d62ddbac6c7c4754bf86be94fddf0d3c10e2827d6eedffd5?environmentId=200`

The dynamic analysis yielded two critical findings:
1.  **Phishing Payload Confirmed:** The sandboxes confirmed the user-facing behavior, capturing screenshots of both the fake "YONO SBI" installation screen and the subsequent SBI credential harvesting page.
2.  **C2 Evasion:** Despite the active phishing and VPN functionality, the sandboxes **did not observe any outbound connections to a malicious C2 server.** This lack of communication is a key finding and strongly suggests the malware has integrated anti-analysis capabilities, remaining dormant in emulator or sandbox environments to hide its full network infrastructure.

## 8. Conclusion

Android/Spy.VpnHijacker.A is a dual-threat espionage tool that combines active phishing with passive, device-wide data interception. Its author is proficient in both creating effective malicious payloads and in defending them with multiple layers of obfuscation, anti-analysis techniques, and deliberate decoys. The successful identification of its anti-sandbox behavior highlights the malware's stealth and the adversary's intent to target real users while evading automated security systems.
