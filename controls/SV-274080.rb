control 'SV-274080' do
  title 'Amazon Linux 2023 must be configured to off-load audit records onto a different system from the system being audited via syslog.'
  desc 'The auditd service does not include the ability to send audit records to a centralized server for management directly. However, it can use a plug-in for audit event multiplexor (audispd) to pass audit records to the local syslog server.'
  desc 'check', 'Verify Amazon Linux 2023 off-loads audit records onto a different system with the following command:

$ more /etc/systemd/journal-upload.conf
[Upload]
URL=192.168.21.2
ServerKeyFile=/etc/ssl/private/journal-upload.pem
ServerCertificateFile=/etc/ssl/certs/journal-upload.pem
TrustedCertificateFile=/etc/ssl/ca/trusted.pem

If all of the entries do not have values, are commented out, or are missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to off-load audit records onto a different system or media from the system being audited.

If using systemd-journal-upload:
Edit "/etc/systemd/journal-upload.conf" with the appropriate configuration:

[Upload]
URL=https://[server.domain]:[port]'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag gid: 'V-274080'
  tag rid: 'SV-274080r1120228_rule'
  tag stig_id: 'AZLX-23-002080'
  tag fix_id: 'F-78076r1120227_fix'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method') == ''
    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^$DefaultNetstreamDriver' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$DefaultNetstreamDriver\s+gtls/) }
    end

    describe 'rsyslog configuration' do
      subject {
        command("grep -i '^$ActionSendStreamDriverMode' #{input('logging_conf_files').join(' ')} | awk -F ':' '{ print $2 }'").stdout
      }
      it { should match(/\$ActionSendStreamDriverMode\s+1/) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
