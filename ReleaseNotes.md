<img align="right" width="200" height="37" src="Gematik_Logo_Flag_With_Background.png" alt="Gematik Logo"/> <br/>

# Release notes lib-vau-csharp for ePA 3.x and above

## Release 1.0.8
- Merge Pull Request of Github
  - Target .NET 8 and .NET Standard 2.0 #16
  - Fix test failures under Linux #17
- Refactoring
  - Remove unused using statements
  - Remove code smells identified by sonarqube
- Update dependencies
  - nunit to Version="4.3.2"
  - NUnit3TestAdapter to Version="5.0.0"
  - Microsoft.NET.Test.Sdk to Version="17.14.1"
  - coverlet.collector to Version="6.0.4"

## Release 1.0.7
- Added missing Release Notes

## Release 1.0.6
- Reverted Changes from 1.0.5 since Specification is not yet ML-KEM
 
## Release 1.0.5
- Updated Bouncy Castle to Version 2.5.1
- Updated Kyber to ML-KEM
- added PU option
 
## Release 1.0.4
- Added missing Release Notes


## Release 1.0.3
- remove all JSON references and conversions.
- fix bug in AES encryption/decryption
- add new test class (EpaDeploymentTest) to communicate with epa deployment environment

## Release 1.0.2

### fixed
- fix bug in aes encryption class, change IV-handling

## Release 1.0.1

### added
- add WebServer / WebClient 
- add integration test
  - Example for VAU handshake with WebClient / WebServer
  - Example for Encryption / Decryption with WebClient / WebServer

### fixed
- error message VauClientStateMachine.CheckRequestByte

## Release 1.0.0
- Initial version
- Available functions:
  - VAU handshake for client & server
  - encryption & decryption of data streams
  - statemachine for VAU client
  - statemachine for VAU server
- LICENSE.md, ReleaseNotes.md, SECURITY.md and LICENSE headers for external release
