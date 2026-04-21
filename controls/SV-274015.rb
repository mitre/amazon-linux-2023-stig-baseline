control 'SV-274015' do
  title 'Amazon Linux 2023 must require users to reauthenticate for privilege escalation.'
  desc 'Without reauthentication, users may access resources or perform tasks for which they do not have authorization.'
  desc 'check', %q(Verify Amazon Linux 2023 requires users to reauthenticate for privilege escalation. 

Ensure that "/etc/sudoers" has no occurrences of "!authenticate" with the following command:

$ sudo grep -ir '!authenticate' /etc/sudoers /etc/sudoers.d/

If any occurrences of "!authenticate" are returned, this is a finding.)
  desc 'fix', %q(Configure Amazon Linux 2023 to not allow users to execute privileged actions without authenticating.

Remove any occurrence of "!authenticate" found in "/etc/sudoers" file or files in the "/etc/sudoers.d" directory.

$ sudo sed -i '/\!authenticate/ s/^/# /g' /etc/sudoers /etc/sudoers.d/*)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000373-GPOS-00156'
  tag satisfies: ['SRG-OS-000373-GPOS-00156', 'SRG-OS-000373-GPOS-00157', 'SRG-OS-000373-GPOS-00158']
  tag gid: 'V-274015'
  tag rid: 'SV-274015r1120033_rule'
  tag stig_id: 'AZLX-23-001015'
  tag fix_id: 'F-78011r1120032_fix'
  tag cci: ['CCI-002038', 'CCI-004895']
  tag nist: ['IA-11', 'SC-11 b']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable within a container without sudo installed', impact: 0.0) {
    !(virtualization.system.eql?('docker') && !command('sudo').exist?)
  }

  describe sudoers(input('sudoers_config_files')) do
    its('settings.Defaults') { should_not include '!authenticate' }
  end
end
