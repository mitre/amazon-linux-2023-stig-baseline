control 'SV-274079' do
  title 'Amazon Linux 2023 must encrypt via the gtls driver the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the SSL, TLS, and DTLS protocols) creates a method to securely encrypt and off-load auditing.'
  desc 'check', %q(Verify Amazon Linux 2023 uses the gtls driver to encrypt audit records off-loaded onto a different system or media from the system being audited with the following command:

$ sudo grep -i '$DefaultNetstreamDriver' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
/etc/rsyslog.conf:$DefaultNetstreamDriver ossl

If the value of the "$DefaultNetstreamDriver" option is not set to "ossl" or the line is commented out, this is a finding.)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-274079'
  tag rid: 'SV-274079r1120724_rule'
  tag stig_id: 'AZLX-23-002075'
  tag fix_id: 'F-78075r1120224_fix'
  tag cci: ['CCI-001851', 'CCI-000366']
  tag nist: ['AU-4 (1)', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') == ''
    describe command("grep -i 'type=\"omfwd\"' #{input('logging_conf_files').join(' ')}") do
      its('stdout') { should match(/^.*:\s*#\s*action\(\s*type\s*=\s*"omfwd"/i) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
