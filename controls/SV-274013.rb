control 'SV-274013' do
  title 'Amazon Linux 2023 must not be configured to bypass password requirements for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization. When operating systems provide the capability to escalate a functional capability, it is critical the user reauthenticate.'
  desc 'check', 'Verify Amazon Linux 2023 is not configured to bypass password requirements for privilege escalation with the following command:

$ sudo grep pam_succeed_if /etc/pam.d/sudo 

If any occurrences of "pam_succeed_if" are returned, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to require users to supply a password for privilege escalation.

Remove any occurrences of "pam_succeed_if " in the "/etc/pam.d/sudo" file.'
  impact 0.5
  tag check_id: 'C-78104r1120025_chk'
  tag severity: 'medium'
  tag gid: 'V-274013'
  tag rid: 'SV-274013r1120027_rule'
  tag stig_id: 'AZLX-23-001005'
  tag gtitle: 'SRG-OS-000312-GPOS-00123'
  tag fix_id: 'F-78009r1120026_fix'
  tag 'documentable'
  tag cci: ['CCI-002165']
  tag nist: ['AC-3 (4)']
end
