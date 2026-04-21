control 'SV-274078' do
  title 'Amazon Linux 2023 must encrypt the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', %q(Verify Amazon Linux 2023 encrypts audit records off-loaded onto a different system or media from the system being audited via rsyslog with the following command:

$ sudo grep -i '$ActionSendStreamDriverMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
/etc/rsyslog.conf:$ActionSendStreamDriverMode 1 

If the value of the "$ActionSendStreamDriverMode" option is not set to "1" or the line is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to encrypt off-loaded audit records via rsyslog by setting the following options in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$ActionSendStreamDriverMode 1'
  impact 0.5
  tag check_id: 'C-78169r1120220_chk'
  tag severity: 'medium'
  tag gid: 'V-274078'
  tag rid: 'SV-274078r1120222_rule'
  tag stig_id: 'AZLX-23-002070'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag fix_id: 'F-78074r1120221_fix'
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
end
