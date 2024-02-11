|`PROJECT`      |`AUTHOR`                                     |`DATE`          |
|---------------|:-------------------------------------------:|:--------------:|
| MEASUREMENTS  |               Daniel Kubec `<niel@rtfm.cz>` | June 2013      |

# Network Measurements and Statistical Analysis

This comprehensive system ensures that each measurements enable immediate and actionable insights, allowing users to discern the implications of the data and how it can be applied to enhance network security, performance, or compliance.

## Abstract

This document delves into Network Security Measurements and Statistical Analysis, establishing a framework for the systemic classification and precise measurement of network endpoints and protocol-specific sessions. It introduces a nuanced approach where each measurement type can be configured for association with specific endpoints, identified by IP address, public key, or reliable fingerprinting of network endpoints.

Furthermore, it categorizes protocols, their specific versions, and the cryptographic algorithms they utilize into distinct security levels ranging from 'insecure', 'vulnerable', 'weak', 'info' and 'recommended' and assesses their compliance with standards such as NIST (National Institute of Standards and Technology). This comprehensive system ensures that each measurements enable immediate and actionable insights, allowing end-users to discern the implications of the data and how it can be applied to enhance network security, performance, or compliance. Through this approach, measurements transcend their role as mere data points, becoming invaluable tools for diagnosing, understanding, and rectifying network-related challenges effectively.

The techniques used can vary significantly in their approach and the depth of information they can uncover. These techniques include passive probing (with knowledge of channel secrets), passive scanning (without knowledge of channel secrets), and active scanning. The total number of measurements and related counters available from these techniques depends greatly on the method employed, as each has different capabilities and access levels to the network data.

## Endpoint Identity

- [IP Address Association] Each measurement can be directly linked to an IP address, serving as a fundamental identifier for network endpoints. This association is crucial for tracking and analyzing network traffic and behavior on a per-device basis, providing a clear and straightforward means of identifying the source and destination of network communications.

- [Public Key Association]  For enhanced identification, measurements can also be associated with stable public keys. This method leverages cryptographic keys that are tied to specific endpoints, offering the identification. The use of stable keys is particularly relevant in environments and contexts where authentication and non-repudiation are paramount.

- [Fingerprint Association] Beyond IP addresses and cryptographic keys, the document introduces the concept of associating measurements with reliable fingerprints. These fingerprints are generated through sophisticated methods that analyze various characteristics of an endpoint, creating a unique identifier that goes beyond conventional methods. This could involve analyzing hardware configurations, software signatures, or network behavior patterns to generate a fingerprint that is not only unique but also resistant to changes or spoofing attempts.


## Measurements

- Measurements provide the raw data collected from individual sessions, acting as the building blocks for more comprehensive analysis. These collected pieces of information, associated with particular measurements, are meticulously compiled to contain sufficient detail for end-users. This ensures that each measurement not only captures the essence of what was measured but also provides a clear basis for understanding why it was measured in the first place. More importantly, the data encompassed within these measurements holds the key to explaining how specific issues or potential problems could be addressed or solved. By integrating this level of detail, the measurements enable immediate and actionable insights, allowing end-users to discern the implications of the data and how it can be applied to enhance network security, performance, or compliance. Through this approach, measurements transcend their role as mere data points, becoming invaluable tools for diagnosing, understanding, and rectifying network-related challenges effectively.

- Composite counter is uniquely associated with a particular measurement, indicating that for every measurement there is a corresponding composite counter. 

- Derived counters, on the other hand, synthesize this information across multiple sessions to offer a macroscopic view of the data, revealing trends and patterns that are not apparent from single sessions alone.

### X509 Measurements

International Telecommunication Union standard format of public key certificates.

- [X509_TRUSTED]
- [X509_SELF_SIGNED]
- [X509_SELF_ISSUED]
- [X509_ISSUER]
- [X509_EXPIRATION_WITHIN_30_DAYS]
- [X509_EXPIRATION_EXCCESSIVE]
- [X509_EXPIRED]
- [X509_REVOKED]
- [X509_CLR]
- [X509_OCSP]
- [X509_OCSP_STAPLING]

### X509 Derived counters

- [X509_VERIFICATION_REQUESTS]
- [X509_VERIFIED]

### TLS Measurements

The Transport Layer Security Protocol

- [TLS_INSECURE_PROTOCOL]
- [TLS_INSECURE_CIPHERSUITE]
- [TLS_INSECURE_RENEGOTIATION]
- [TLS_WEAK_CIPHERSUITE]
- [TLS_WEAK_RESUMPTION]
- [TLS_RECOMMENDED_CIPHERSUITE]
- [TLS_EXTENDED_MASTER_SECRET]
- [TLS_MUTUAL AUTHENTICATION]
- [TLS_NO_AUTHENTICATION]
- [TLS_NO_ENCRYPTION]
- [TLS_FORWARD_SECRECY]
- [TLS_PERFECT_FORWARD_SECRECY]
- [TLS_NEXT_PROTOCOL_NEGOTIATION]
- [TLS_APPLICATION_LAYER_PROTOCOL_NEGOTIATION]
- [TLS_COMPLIANCE_NIST]
- [TLS_QUANTUM_SAFE]
- [TLS_QUANTUM_HYBRID]

### TLS Vulnerability Measurements

- [TLS_TRIPLE_HANDSHAKE_ATTACK]
- [TLS_DOWNGRADE_ATTACK]
- [TLS_POODLE_ATTACK]
- [TLS_FREAK_ATTACK]
- [TLS_BEAST_ATTACK]
- [TLS_CRIME_ATTACK]
- [TLS_LUCKY13_ATTACK]
- [TLS_RACCOON_ATTACK]

### TLS Derived counters

- [TLS_RECORD_PLAINTEXT]
- [TLS_RECORD_ENCRYPTED]
- [TLS_RECORD_DECRYPTED]
- [TLS_HANDSHAKE_FULL]
- [TLS_HANDSHAKE_ABBREVIATED]
- [TLS_HANDSHAKE_NEGOTIATED]
- [TLS_HANDSHAKE_VERIFIED]
- [TLS_CIPHERSUITES_CLIENT_SUPPORT]
- [TLS_CIPHERSUITES_SERVER_SUPPORT]
- [TLS_CIPHERSUITES_NEGOTIATED]
- [TLS_AUTHENTICATION_CLIENT_SUPPORT]
- [TLS_AUTHENTICATION_SERVER_SUPPORT]
- [TLS_AUTHENTICATION_NEGOTIATED]
- [TLS_KEY_EXCHANGE_CLIENT_SUPPORT]
- [TLS_KEY_EXCHANGE_SERVER_SUPPORT]
- [TLS_KEY_EXCHANGE_NEGOTIATED]
- [TLS_DECRYPTION_RATIO_TOTAL]
- [TLS_DECRYPTION_RATIO_PER_CIPHERSUITE]
- [TLS_DECRYPTION_AVG_SPEED_TOTAL]
- [TLS_DECRYPTION_AVG_SPEED_PER_CIPHERSUITE]
- [TLS_DECRYPTION_MEDIAN_SPEED_TOTAL]
- [TLS_DECRYPTION_MEDIAN_SPEED_PER_CIPHERSUITE]
- [TLS_DECRYPTION_MAX_SPEED_TOTAL]
- [TLS_DECRYPTION_MAX_SPEED_PER_CIPHERSUITE]
- [TLS_DECRYPTION_MIN_SPEED_TOTAL]
- [TLS_DECRYPTION_MIN_SPEED_PER_CIPHERSUITE]
- [TLS_APPLICATION_LAYER_NEGOTIATION_PER_PROTOCOL]

### TLS_INSECURE_PROTOCOL

TLS (Transport Layer Security) protocols older than 1.2 and 1.3 are considered insecure for several key reasons, each of which relates to the evolution of internet security standards and the discovery of vulnerabilities in older versions of the protocol.

TLS 1.0 and 1.1 rely on cryptographic algorithms and standards that are no longer considered secure by today's security community. This includes the use of weaker hash functions (like MD5 and SHA-1) and encryption algorithms (such as DES and 3DES) that are vulnerable to brute force attacks and other cryptographic attacks.

The insecurity of TLS versions older than 1.2 stems from their use of vulnerable cryptographic algorithms, susceptibility to specific attacks, and lack of support for stronger, more secure cipher suites. In contrast, TLS 1.2 and 1.3 provide enhancements that address these weaknesses, including mandatory support for PFS, stronger cryptographic algorithms, and a more secure protocol design. Consequently, organizations and service providers are encouraged to disable TLS 1.0 and 1.1 in favor of TLS 1.2 and 1.3 to ensure the security and privacy of data in transit.


### TLS_INSECURE_CIPHERSUITE

Insecure cipher suites represent a critical security vulnerability because they rely on cryptographic algorithms that are either outdated, have known vulnerabilities, or both. These vulnerabilities can be exploited by attackers to decrypt, modify, or intercept data that is supposed to be secured. The measurement of an insecure cipher suite not only indicates the presence of such a vulnerability but can also explain the exact reasons why it's considered insecure. 

Here's an example to illustrate this:
[TLS_DH_anon_WITH_SEED_CBC_SHA](https://ciphersuite.info/cs/TLS_DH_anon_WITH_SEED_CBC_SHA/)

### TLS_WEAK_CIPHERSUITE

A weak cipher suite may not have direct vulnerabilities like those found in insecure cipher suites with known exploits, but its security can be generally weak, making it susceptible under certain conditions or when combined with other security weaknesses. This weakness often stems from using cryptographic algorithms or protocols that are outdated, have theoretical vulnerabilities, or rely on insufficient key lengths. Here's an example to illustrate such a scenario:

Here's an example to illustrate this:
[TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256](https://ciphersuite.info/cs/TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256/)


### TLS_EXTENDED_MASTER_SECRET

The Extended Master Secret Extension modifies the way the master secret is calculated. Instead of using just the pre-master secret and random values, it includes a session hash that encompasses all the handshake messages sent and received up to the point of the master secret calculation. This results in a unique master secret for each session, even if the same pre-master secret is reused.

In summary, the TLS Extended Master Secret Extension in TLS 1.2 enhances the security of TLS sessions by ensuring that the master secret and by extension, the session keys are uniquely tied to the complete handshake history. This makes it more difficult for attackers to compromise TLS sessions through MITM, triple handshake, renegotiation, and session resumption attacks.

[RFC-7627](https://datatracker.ietf.org/doc/html/rfc7627)
Transport Layer Security Session Hash and Extended Master Secret Extension.

### TLS_TRIPLE_HANDSHAKE_ATTACK

The Triple Handshake Attack is a sophisticated form of Man-in-the-Middle (MITM) attack specifically targeting the TLS protocol. In this attack, the attacker manipulates the handshake process between the client and the server in such a manner that both parties end up deriving the same master secret despite not directly communicating with each other in a secure manner. This attack exploits the TLS handshake mechanism's lack of binding between the master secret and the specific attributes of the session, such as the server's identity.

Compromising Additional Authentication: What makes the Triple Handshake Attack particularly dangerous is that it can also compromise additional authentication mechanisms layered on top of TLS. Furthermore, it can create vulnerability for any side-channel authentication that is based on the master secret. Since the master secret is used to derive the session keys, if an attacker can manipulate the process to derive the same master secret, they can potentially bypass these additional authentication checks. The attack essentially breaks the assumed binding between the session's security properties and its unique master secret, making even strong forms of authentication vulnerable under certain conditions.

### TLS_DOWNGRADE_ATTACK

To work around interoperability problems with legacy servers, many
TLS client implementations do not rely on the TLS protocol version
negotiation mechanism alone but will intentionally reconnect using a
downgraded protocol if initial handshake attempts fail.  Such clients
may fall back to connections in which they announce a version as low
as TLS 1.0 (or even its predecessor, Secure Socket Layer (SSL) 3.0)
as the highest supported version.

While such fallback retries can be a useful last resort for
connections to actual legacy servers, there's a risk that active
attackers could exploit the downgrade strategy to weaken the
cryptographic security of connections.  Also, handshake errors due to
network glitches could similarly be misinterpreted as interaction
with a legacy server and result in a protocol downgrade.

[RFC-7507](https://datatracker.ietf.org/doc/html/rfc7507)
Signaling Cipher Suite Value (SCSV) that prevents protocol downgrade attacks.


### TLS_POODLE_ATTACK

POODLE (which stands for "Padding Oracle On Downgraded Legacy Encryption") is a security vulnerability which takes advantage of the fallback to SSL 3.0.[1][2][3] If attackers successfully exploit this vulnerability, on average, they only need to make 256 SSL 3.0 requests to reveal one byte of encrypted messages. Bodo Möller, Thai Duong and Krzysztof Kotowicz from the Google Security Team discovered this vulnerability; they disclosed the vulnerability publicly on October 14, 2014 (despite the paper being dated "September 2014" [1]).[4] On December 8, 2014 a variation of the POODLE vulnerability that affected TLS was announced.[5]

The CVE-ID associated with the original POODLE attack is CVE-2014-3566. F5 Networks filed for CVE-2014-8730 as well, see POODLE attack against TLS section below.

Prevention:

The authors of the paper on POODLE attacks encourage client and server implementation of TLS_FALLBACK_SCSV,[6] which will make downgrade attacks impossible.


### TLS_FREAK_ATTACK

The FREAK attack is a SSL/TLS vulnerability that allows attackers to intercept HTTPS connections between vulnerable clients and servers and force them to use 'export-grade' cryptography, which can then be decrypted or altered. Websites that support RSA export cipher suites are at risk to having HTTPS connections intercepted.


### TLS_BEAST_ATTACK

Browser Exploit Against SSL/TLS (BEAST) is an attack that exploits a vulnerability in the Transport-Layer Security (TLS) 1.0 and older SSL protocols, using the cipher block chaining (CBC) mode encryption. It allows attackers to capture and decrypt HTTPS client-server sessions and obtain authentication tokens. It combines a man-in-the-middle attack (MitM), record splitting, and chosen boundary attack.

The theoretical vulnerability was described by Phillip Rogaway as early as 2002, and a proof of concept was demonstrated in 2011 by security researchers Thai Duong and Juliano Rizzo. The BEAST attack is similar to protocol downgrade attacks such as POODLE in that it also uses a MITM approach and exploits vulnerabilities in CBC. 


### TLS_CRIME_ATTACK

Compression Ratio Info-leak Made Easy (CRIME) is a security exploit against secret web cookies over connections using the HTTPS and SPDY protocols that also use data compression. When used to recover the content of secret authentication cookies, it allows an attacker to perform session hijacking on an authenticated web session, allowing the launching of further attacks.

CRIME is a client-side attack, but the server can protect the client by refusing to use the feature combinations which can be attacked. For CRIME, the weakness is Deflate compression. This alert is issued if the server accepts Deflate compression.

Remediation
CRIME can be defeated by preventing the use of compression, either at the client end, by the browser disabling the compression of HTTPS requests, or by the website preventing the use of data compression on such transactions using the protocol negotiation features of the TLS protocol. As detailed in The Transport Layer Security (TLS) Protocol Version 1.2, the client sends a list of compression algorithms in its ClientHello message, and the server picks one of them and sends it back in its ServerHello message. The server can only choose a compression method the client has offered, so if the client only offers 'none' (no compression), the data will not be compressed. Similarly, since 'no compression' must be allowed by all TLS clients, a server can always refuse to use compression.

### TLS_LUCKY13_ATTACK

A Lucky Thirteen attack is a cryptographic timing attack against implementations of the Transport Layer Security (TLS) protocol that use the CBC mode of operation, first reported in February 2013 by its developers Nadhem J. AlFardan and Kenny Paterson of the Information Security Group at Royal Holloway, University of London.[1][2]

Attack
It is a new variant of Serge Vaudenay's padding oracle attack that was previously thought to have been fixed, that uses a timing side-channel attack against the message authentication code (MAC) check stage in the TLS algorithm to break the algorithm in a way that was not fixed by previous attempts to mitigate Vaudenay's attack.[3]

"In this sense, the attacks do not pose a significant danger to ordinary users of TLS in their current form. However, it is a truism that attacks only get better with time, and we cannot anticipate what improvements to our attacks, or entirely new attacks, may yet be discovered." — Nadhem J. AlFardan and Kenny Paterson[1]

The researchers only examined Free Software implementations of TLS and found all examined products to be potentially vulnerable to the attack. They have tested their attacks successfully against OpenSSL and GnuTLS. Because the researchers applied responsible disclosure and worked with the software vendors, some software updates to mitigate the attacks were available at the time of publication.[2]

Martin R. Albrecht and Paterson have since demonstrated a variant Lucky Thirteen attack against Amazon's s2n TLS implementation, even though s2n includes countermeasures intended to prevent timing attacks.[4]

### TLS_RACCOON_ATTACK

Raccoon is a timing vulnerability in the TLS specification that affects HTTPS and other services that rely on SSL and TLS. These protocols allow everyone on the Internet to browse the web, use email, shop online, and send instant messages without third-parties being able to read the communication.

Raccoon allows attackers under certain conditions to break the encryption and read sensitive communications. The vulnerability is really hard to exploit and relies on very precise timing measurements and on a specific server configuration to be exploitable.

[RACCOON_ATTACK](https://raccoon-attack.com/)

### TLS_QUANTUM_SAFE

As quantum computing continues to evolve and advance, a large quantum computer will be able to run a "SHOR" algorithm that can break the current TLS communication algorithms (RSA/ECC) in a matter of minutes. While large quantum computers are not available today, any TLS data-in-transit that has been snooped and stored can be breached when these large quantum computers are made available. Data has a long shelf life so it is critical that Key Protect supports quantum safe cryptographic algorithms to secure TLS communications.

To keep your in-transit data resilient, Key Protect has introduced the ability to use a quantum safe enabled TLS connection to ensure that your data is secure during the key exchange process.

[Post-Quantum Cryptography ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)

### TLS_QUANTUM_HYBRID

Hybrid mode uses a combination of a quantum safe algorithm and classic key exchange algorithms to protect your data while in transit. The classic elliptic algorithm and the quantum safe algorithm are used in a key exchange mechanism to cryptographically protect data. 

[Post-Quantum Cryptography ](https://csrc.nist.gov/Projects/Post-Quantum-Cryptography)

