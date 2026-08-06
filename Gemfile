source 'https://rubygems.org'

# channel_rb (sibling repo, no gemspec) is wired via $LOAD_PATH in
# lib/hub_service_rb.rb — its deps (oj, iodine) are declared here.
gem 'oj', '3.13.23'
gem 'iodine', '0.7.58'
gem 'minitest', '~> 5.20'

# ed25519: system ruby's openssl (LibreSSL) lacks OpenSSL::PKey::ED25519.

# System ruby (2.6 + LibreSSL) lacks OpenSSL::PKey::ED25519, so ed25519
# signing uses the RubyCrypto ed25519 gem (pure C ref impl, RFC 8032).
gem 'ed25519', '1.3.0'
