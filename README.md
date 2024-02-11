# Network Measurements and Statistical Analysis

## Abstract

This document delves into Network Security Measurements and Statistical Analysis, establishing a framework for the systemic classification and precise measurement of network endpoints and protocol-specific sessions. It introduces a nuanced approach where each measurement type can be configured for association with specific endpoints, identified by IP address, public key, or reliable fingerprinting of network endpoints.

Furthermore, it categorizes protocols, their specific versions, and the cryptographic algorithms they utilize into distinct security levels ranging from 'insecure', 'vulnerable', 'weak', 'info' and 'recommended' and assesses their compliance with standards such as NIST (National Institute of Standards and Technology). This comprehensive system ensures that each measurement possesses a uniform and unique identification, based on type, endpoint, and additional data, enabling a detailed evaluation of security postures and adherence to cybersecurity best practices.

## Endpoint

- [IP Address Association] Each measurement can be directly linked to an IP address, serving as a fundamental identifier for network endpoints. This association is crucial for tracking and analyzing network traffic and behavior on a per-device basis, providing a clear and straightforward means of identifying the source and destination of network communications.

- [Public Key Association]  For enhanced security and identification, measurements can also be associated with stable public keys. This method leverages cryptographic keys that are tied to specific endpoints, offering a higher level of security by ensuring that the identification is not only unique but also secured against impersonation or spoofing attacks. The use of stable public keys is particularly relevant in environments where authentication and non-repudiation are paramount.

- [Fingerprint Association] Beyond IP addresses and cryptographic keys, the document introduces the concept of associating measurements with reliable fingerprints. These fingerprints are generated through sophisticated methods that analyze various characteristics of an endpoint, creating a unique identifier that goes beyond conventional methods. This could involve analyzing hardware configurations, software signatures, or network behavior patterns to generate a fingerprint that is not only unique but also resistant to changes or spoofing attempts.


## Measurements

- Measurements provide the raw data collected from individual sessions, acting as the building blocks for more comprehensive analysis. These collected pieces of information, associated with particular measurements, are meticulously compiled to contain sufficient detail for end-users. This ensures that each measurement not only captures the essence of what was measured but also provides a clear basis for understanding why it was measured in the first place. More importantly, the data encompassed within these measurements holds the key to explaining how specific issues or potential problems could be addressed or solved. By integrating this level of detail, the measurements enable immediate and actionable insights, allowing end-users to discern the implications of the data and how it can be applied to enhance network security, performance, or compliance. Through this approach, measurements transcend their role as mere data points, becoming invaluable tools for diagnosing, understanding, and rectifying network-related challenges effectively.

- Composite counter is uniquely associated with a particular measurement, indicating that for every measurement there is a corresponding composite counter. 

- Derived counters, on the other hand, synthesize this information across multiple sessions to offer a macroscopic view of the data, revealing trends and patterns that are not apparent from single sessions alone.

### X509 Measurements

International Telecommunication Union standard defining the format of public key certificates.

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
- [TLS_PERFECT_FORWARD_SECRECY]
- [TLS_NEXT_PROTOCOL_NEGOTIATION]
- [TLS_APPLICATION_LAYER_PROTOCOL_NEGOTIATION]
- [TLS_COMPLIANCE_NIST]
- [TLS_TRIPLE_HANDSHAKE_ATTACK]
- [TLS_DOWNGRADE_ATTACK]
- [TLS_POODLE]
- [TLS_FREAK]
- [TLS_BEAST]
- [TLS_CRIME]
- [TLS_LUCKY]
- [TLS_HEARTBLEED]
-

### TLS_TRIPLE_HANDSHAKE_ATTACK

The Triple Handshake Attack is a sophisticated form of Man-in-the-Middle (MITM) attack specifically targeting the TLS protocol. In this attack, the attacker manipulates the handshake process between the client and the server in such a manner that both parties end up deriving the same master secret despite not directly communicating with each other in a secure manner. This attack exploits the TLS handshake mechanism's lack of binding between the master secret and the specific attributes of the session, such as the server's identity.

Compromising Additional Authentication: What makes the Triple Handshake Attack particularly dangerous is that it can also compromise additional authentication mechanisms layered on top of TLS. Since the master secret is used to derive the session keys for encryption and MAC (Message Authentication Code) operations, if an attacker can manipulate the process to derive the same master secret, they can potentially bypass these additional authentication checks. The attack essentially breaks the assumed binding between the session's security properties and its unique master secret, making even strong forms of authentication vulnerable under certain conditions.

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

Signaling Cipher Suite Value (SCSV) that prevents protocol downgrade attacks
[RFC-7507](ihttps://datatracker.ietf.org/doc/html/rfc7507) 

### TLS_EXTENDED_MASTER_SECRET

The Extended Master Secret Extension modifies the way the master secret is calculated. Instead of using just the pre-master secret and random values, it includes a session hash that encompasses all the handshake messages sent and received up to the point of the master secret calculation. This results in a unique master secret for each session, even if the same pre-master secret is reused.

In summary, the TLS Extended Master Secret Extension in TLS 1.2 enhances the security of TLS sessions by ensuring that the master secret—and by extension, the session keys—are uniquely tied to the complete handshake history. This makes it more difficult for attackers to compromise TLS sessions through MITM, triple handshake, renegotiation, and session resumption attacks.

### TLS Derived counters

- [TLS_RECORD_PLAINTEXT]
- [TLS_RECORD_ENCRYPTED]
- [TLS_RECORD_DECRYPTED]
- [TLS_HANDSHAKE_FULL]
- [TLS_HANDSHAKE_ABBREVIATED]
- [TLS_HANDSHAKE_NEGOTIATED]
- [TLS_HANDSHAKE_VERIFIED]
- [TLS_CIPHERSUITES_SUPPORTED]
- [TLS_CIPHERSUITES_NEGOTIATED]
- [TLS_AUTHENTICATION_SUPPORTED]
- [TLS_AUTHENTICATION_NEGOTIATED]
- [TLS_KEY_EXCHANGE_SUPPORTED]
- [TLS_KEY_EXCHANGE_NEGOTIATED]

