# Changelog

## [Unreleased]

### Added
- Initial release. `cognito-broker` mints a Cognito access token with
  the `client_credentials` grant, reading the app client's coordinates
  from an AWS Systems Manager parameter tree under an ordinary AWS
  session.

  The design decision worth recording: **no service in the path.** A
  token broker would work, but the callers can already reach AWS, so a
  service would add a deployment, a release cycle and an outage mode
  without adding a capability. Putting the credential in SSM makes
  authorization an IAM question, answered by the same policy that
  governs everything else the caller reaches.

  Local and CI runs are consequently the same command, differing only in
  how the AWS session resolves — which the credential chain already
  answers.

  Shipped as a binary rather than a library because the suites that need
  it are written in different languages: one binary they all shell out
  to is one implementation, where a library would be three that drift.
