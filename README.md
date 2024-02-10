# Network Measurements and Statistical Analysis

## Abstract

This document delves into Network Security Measurements and Statistical Analysis, establishing a framework for the systemic classification and precise measurement of network endpoints and protocol-specific sessions. It introduces a nuanced approach where each measurement type can be configured for association with specific endpoints, identified by IP address, public key, or reliable fingerprinting of network endpoints.

Furthermore, it categorizes protocols, their specific versions, and the cryptographic algorithms they utilize into distinct security levels ranging from 'insecure', 'vulnerable', 'weak', 'info' and 'recommended' and assesses their compliance with standards such as NIST (National Institute of Standards and Technology). This comprehensive system ensures that each measurement possesses a uniform and unique identification, based on type, endpoint, and additional data, enabling a detailed evaluation of security postures and adherence to cybersecurity best practices.

## Measurements

Measurements provide the raw data collected from individual sessions, acting as the building blocks for more comprehensive analysis. Derived counters, on the other hand, synthesize this information across multiple sessions to offer a macroscopic view of the data, revealing trends and patterns that are not apparent from single sessions alone.

### X509

International Telecommunication Union standard defining the format of public key certificates.

- [X509_TRUSTED](#x509-trusted)
- [X509_SELF_SIGNED](#x509-self-signed)
- [X509_SELF_ISSUED](#x509-self-issued)
- [X509_ISSUER](#x509-issuer)
- [X509_EXPIRES_30_DAYS](#x509-expires-after30days)
- [X509_EXPIRES_EXCCESSIVE](#x509-expires-exccessive)
- [X509_EXPIRED](#x509-expired)
- [X509_REVOKED](#x509-revoked)
- [X509_CLR](#x509-clr)
- [X509_OCSP](#x509-ocsp)
- [X509_OCSP_STAPLING](#x509-ocsp-stapling)

### TLS

The Transport Layer Security Protocol

- [TLS_INSECURE_PROTOCOL](#tls-insecure-protocol)
- [TLS_INSECURE_CIPHERSUITE](#tls-insecure-ciphersuite)
- [TLS_INSECURE_RENEGOTIATION](#tls-insecure-renegotiation)
- [TLS_WEAK_CIPHERSUITE](#tls-weak-ciphersuite)
- [TLS_WEAK_RESUMPTION](#tls-weak-resumption)
- [TLS_VULN_TRIPLE_HANDSHAKE_ATTACK](#tls-vuln-triple-handshake-attack)
- [TLS_VULN_DOWNGRADE_ATTACK](#tls-vuln-downgrade-attack)
- [TLS_RECOMMENDED_CIPHERSUITE](#tls-recommended-ciphersuite)
- [TLS_EXTENDED_MASTER_SECRET](#tls-extended-master-secret)
- [TLS_MUTUAL AUTHENTICATION](#tls-mutual-authentication)
- [TLS_PERFECT_FORWARD_SECRECY](#tls-perfect-forward-secrecy)
- [TLS_NEXT_PROTOCOL_NEGOTIATION](#tls-extension-npn)
- [TLS_APPLICATION_LAYER_PROTOCOL_NEGOTIATION](#tls-extension-alpn)
- [TLS_COMPLIANCE_NIST](#tls-compliance-nist)


[X509_SELF_SIGNED]: #x509-self-signed

### TLS_VULN_TRIPLE_HANDSHAKE_ATTACK
[TLS_VULN_TRIPLE_HANDSHAKE_ATTACK]: #tls-vuln-triple-handshake-attack

The Triple Handshake Attack is a sophisticated form of Man-in-the-Middle (MITM) attack specifically targeting the TLS protocol. In this attack, the attacker manipulates the handshake process between the client and the server in such a manner that both parties end up deriving the same master secret despite not directly communicating with each other in a secure manner. This attack exploits the TLS handshake mechanism's lack of binding between the master secret and the specific attributes of the session, such as the server's identity.

Compromising Additional Authentication: What makes the Triple Handshake Attack particularly dangerous is that it can also compromise additional authentication mechanisms layered on top of TLS. Since the master secret is used to derive the session keys for encryption and MAC (Message Authentication Code) operations, if an attacker can manipulate the process to derive the same master secret, they can potentially bypass these additional authentication checks. The attack essentially breaks the assumed binding between the session's security properties and its unique master secret, making even strong forms of authentication vulnerable under certain conditions.

### TLS_VULN_DOWNGRADE_ATTACK
[TLS_VULN_DOWNGRADE_ATTACK]: #tls-vuln-downgrade-attack



### TLS_EXTENDED_MASTER_SECRET
[TLS_EXTENDED_MASTER_SECRET]: #tls-extended-master-secret

The Extended Master Secret Extension modifies the way the master secret is calculated. Instead of using just the pre-master secret and random values, it includes a session hash that encompasses all the handshake messages sent and received up to the point of the master secret calculation. This results in a unique master secret for each session, even if the same pre-master secret is reused.

In summary, the TLS Extended Master Secret Extension in TLS 1.2 enhances the security of TLS sessions by ensuring that the master secret—and by extension, the session keys—are uniquely tied to the complete handshake history. This makes it more difficult for attackers to compromise TLS sessions through MITM, triple handshake, renegotiation, and session resumption attacks.
