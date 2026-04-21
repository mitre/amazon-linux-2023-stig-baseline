control 'SV-274162' do
  title 'Amazon Linux 2023 password-auth must be configured to use a sufficient number of hashing rounds.'
  desc 'Unapproved mechanisms, used for authentication to the cryptographic module are not verified and therefore, cannot be relied upon to provide confidentiality or integrity, and DOD data may be compromised.

Operating systems utilizing encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules. 

FIPS 140-2/140-3 is the current standard for validating that mechanisms used to access cryptographic modules utilize authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general purpose computing system.'
  desc 'check', 'Verify Amazon Linux 2023 has the required number of rounds for the password hashing algorithm is configured in password-auth with the following command:

$ sudo grep rounds /etc/pam.d/password-auth
password sufficient pam_unix.so sha512 rounds=100000

If a matching line is not returned or "rounds" is less than "100000", this a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to use 100000 hashing rounds for hashing passwords.

Add or modify the following line in "/etc/pam.d/password-auth" and set "rounds" to "100000".

password sufficient pam_unix.so sha512 rounds=100000'
  impact 0.5
  tag check_id: 'C-78253r1120472_chk'
  tag severity: 'medium'
  tag gid: 'V-274162'
  tag rid: 'SV-274162r1120474_rule'
  tag stig_id: 'AZLX-23-002490'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-78158r1120473_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-000196', 'CCI-000803', 'CCI-004062']
  tag nist: ['IA-5 (1) (c)', 'IA-7', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  expected_line = 'password sufficient pam_unix.so sha512'
  pam_auth_files = input('pam_auth_files')
  password_hash_rounds = input('password_hash_rounds')

  describe pam(pam_auth_files['password-auth']) do
    its('lines') { should match_pam_rule(expected_line).any_with_integer_arg('rounds', '>=', password_hash_rounds) }
  end
end
