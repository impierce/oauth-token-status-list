# OAuth Token Status List

This is a Rust library for the IETF OAuth Token Status List (TSL) specification developed by the [Web Authorization Protocol
Working Group](https://datatracker.ietf.org/wg/oauth/about/).

| Specification                        | Version                                                                                                                           |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------- |
| IETF OAuth Token Status List         | [Working Group Draft 10 published: 25 March 2025](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/10/)              |


## Description

The purpose of this repository is the Rust implementation of the TSL specification. This repository seeks to be completely agnostic.
Any use-case specific implementation remains outside of the scope of this repository.
Therefore, to best describe the use and capabilities of this repo the description of the TSL specification itself fits best. 
All implementations seek to be one on one with the TSL spec, merely translated to Rust code, any deviations should be reported.
The following description is copied from the TSL spec:

"The TSL specification defines a mechanism, data structures and processing rules for representing the status of tokens secured by
JSON Object Signing and Encryption (JOSE) or CBOR Object Signing and Encryption (COSE), such as JWT, SD-JWT VC, CBOR Web Token and ISO mdoc.
It also defines an extension point and a registry for future status mechanisms."

Below you will find a checklist detailing the exact coverage of the TSL spec in this repo.

# TSL Implementation Checklist 📋

This table tracks our implementation progress toward full OAuth Token Status List specification compliance.
Keep in mind this specification list is based off the version noted at the top of this README.



| Spec. Reference     | Feature                                                                          | Implemented |
| ------------------- | -------------------------------------------------------------------------------- | :---------: |
| **1.**              | Introduction                                                                     |   **N/A**   |
| **2.**              | Conventions and Definitions                                                      |   **N/A**   |
| **3.**              | Terminology                                                                      |   **N/A**   |
| **4.**              | **Status List**                                                                  |             |
| 4.1                 | Compressed Byte Array                                                            |     ✅      |
| 4.1.1-3             | Set Byte Array                                                                   |     ✅      |
| 4.1.4               | Compress Byte Array                                                              |     ✅      |
| 4.2                 | Status List in JSON Format                                                       |     ✅      |
| 4.2.1               | Support optional `aggregation_uri`                                               |     ❌      |
| 4.3                 | Status List in CBOR Format                                                       |     ❌      |
| 4.3.1               | Support optional `aggregation_uri`                                               |     ❌      |
| **5.**              | **Status List Token**                                                            |             |
| 5.1                 | Status List Token in JWT Format                                                  |     ✅      |
| 5.1.0               | Support optional `exp`                                                           |     ✅      |
| 5.1.0               | Support optional `ttl`                                                           |     ❌      |
| 5.1.2               | Secure with cryptographic signature or MAC algorithm.                            |     ✅      |
| 5.1.3               | JWT validation                                                                   |     ✅      |
| 5.1.4               | Additional rules and policies of RP                                              |     ❌      |
| 5.2.                | Status List Token in CWT Format                                                  |     ❌      |
| 5.2.0               | Support optional `exp` and `ttl`                                                 |     ❌      |
| 5.2.2               | Secure with cryptographic signature or MAC algorithm.                            |     ❌      |
| 5.2.3               | CWT validation                                                                   |     ❌      |
| 5.2.4               | Additional rules and policies of RP                                              |     ❌      |
| **6.**              | **Referenced Token**                                                             |             |
| 6.1.                | Status Claim                                                                     |     ✅      |
| 6.2.                | Referenced Token in JOSE                                                         |     ✅      |
| 6.3.                | Referenced Token in COSE                                                         |     ❌      |
| 6.3.1               | CWT in ISO mdoc                                                                  |     ❌      |
| **7.**              | **Status Types**                                                                 |             |
| 7.1.                | Status Types Values                                                              |     ✅      |
| 7.1.1               | Support Status Type `suspended`                                                  |     ✅      |
| **8.**              | **Verification and Processing**                                                  |             |
| 8.1.                | Status List Request                                                              |     ✅      |
| 8.1.0               | Support CORS and/or alternatives                                                 |     ✅      |
| 8.1.1               | Handle GET request Accept Header                                                 |     ✅      |
| 8.1.2               | 2xx response containing Status List                                              |     ✅      |
| 8.1.3               | 3xx response with redirect uri                                                   |     ✅      |
| 8.2.                | Status List Response                                                             |     ✅      |
| 8.2.1               | Gzip Content-Encoding                                                            |     ✅      |
| 8.3.                | Validation Rules                                                                 |     ✅      |
| 8.3.0               | Validate Referenced Token as JWT/CWT                                             |     ✅      |
| 8.3.1               | Validate Status Claim as per 6.2/3                                               |     ✅      |
| 8.3.2               | Resolve Status List Token                                                        |     ✅      |
| 8.3.3               | Validate Status List Token as JWT/CWT and 5.1/2                                  |     ✅      |
| 8.3.4               | Check Status List Token Claims                                                   |     ✅      |
| 8.3.5               | Decompress Status List compatible with DEFLATE and ZLIB                          |     ✅      |
| 8.3.6               | Retrieve Status                                                                  |     ✅      |
| 8.3.7               | Check Status                                                                     |     ✅      |
| 8.4.                | Historical resolution                                                            |     ❌      |
| 8.4.1               | Support time query parameter                                                     |     ❌      |
| **9.**              | **Status List Aggregation**                                                      |             |
| 9.1.                | Issuer Metadata                                                                  |     ❌      |
| 9.2.                | Status List Parameter                                                            |     ❌      |
| 9.3.                | Status List Aggregation in JSON Format                                           |     ❌      |
| **10.**             | **X.509 Certificate Extensions**                                                 |             |
| 10.1.               | Extended Key Usage Extension                                                     |     ❌      |
| **11.**             | **Security Considerations**                                                      |   **N/A**   |
| **12.**             | **Privacy Considerations**                                                       |             |
| 12.1.               | Observability of Issuers                                                         |     ❌      |
| 12.2.               | Malicious Issuers                                                                |     ❌      |
| 12.3.               | Observability of Relying Parties                                                 |     ❌      |
| 12.4.               | Observability of Outsiders                                                       |     ❌      |
| 12.5.               | Unlinkability                                                                    |     ❌      |
| 12.5.1.             | Colluding Relying Parties                                                        |     ❌      |
| 12.5.2.             | Colluding Status Issuer and Relying Party                                        |     ❌      |
| 12.6.               | External Status Provider for Privacy                                             |     ❌      |
| 12.7.               | Historical Resolution                                                            |     ❌      |
| 12.8.               | Status Types                                                                     |     ❌      |
| **13.**             | **Implementation Considerations**                                                |             |
| **14.**             | **IANA Considerations**                                                          |   **N/A**   |

