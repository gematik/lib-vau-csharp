<img align="right" width="200" height="37" src="Gematik_Logo_Flag_With_Background.png" alt="Gematik Logo"/> <br/>

# Release notes lib-vau-csharp for ePA 3.x and above

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
