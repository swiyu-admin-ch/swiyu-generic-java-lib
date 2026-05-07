# Trust Statement Verifier (swiyu-ts-verifier)

## Features

- **Cryptographic Verification**: Trust statements are cryptographically verified to ensure that they have not been tampered with. This verification utilizes a trusted root
- **Validity Verification**: Trust statements are verified to be valid - this means neither revoked, suspended or expired.
- **Generate TrustMarks**: Trust Marks give an easy overview what level of trust can be given to an actor

## Dependencies

- **swiyu-token-status-list**: Verification of Trust Statement Status
- **swiyu-jwt-util**: Verification of Trust Statement signatures
- **Jackson**: JSON processing

## License

This project is licensed under the terms of the MIT license. See the [LICENSE](/LICENSE) file for details.

---

For feedback and contributions, see [CONTRIBUTING.md](/CONTRIBUTING.md).