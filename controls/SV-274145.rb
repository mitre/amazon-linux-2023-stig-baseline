control 'SV-274145' do
  title 'Amazon Linux 2023 must define default permissions for all authenticated users in such a way that the user can only read and modify their own files.'
  desc 'Setting the most restrictive default permissions ensures that when new
accounts are created, they do not have unnecessary access.'
  desc 'check', 'Verify Amazon Linux 2023 defines default permissions for all authenticated users in such a way that the user can only read and modify their own files with the following command:

Note: If the value of the "UMASK" parameter is set to "000" in "/etc/login.defs" file, the Severity is raised to a CAT I.

# grep -i umask /etc/login.defs
UMASK 077

If the value for the "UMASK" parameter is not "077", or the "UMASK" parameter is missing or is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to define default permissions for all authenticated users in such a way that the user can only read and modify their own files.

Add or edit the lines for the "UMASK" parameter in the "/etc/login.defs" file to "077":

UMASK 077'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000480-GPOS-00228'
  tag gid: 'V-274145'
  tag rid: 'SV-274145r1120423_rule'
  tag stig_id: 'AZLX-23-002410'
  tag fix_id: 'F-78141r1120422_fix'
  tag cci: ['CCI-000366']
  tag nist: ['CM-6 b']
  tag 'host'
  tag 'container'

  modes_for_shells = input('modes_for_shells')

  describe login_defs do
    its('UMASK') { should cmp modes_for_shells['default_umask'] }
  end
end
