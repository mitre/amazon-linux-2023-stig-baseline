control 'SV-274185' do
  title 'Amazon Linux 2023 must remove all software components after updated versions have been installed.'
  desc 'Previous versions of software components that are not removed from the information system after updates have been installed may be exploited by some adversaries.'
  desc 'check', 'Verify Amazon Linux 2023 removes all software components after updated versions have been installed with the following command:

$ grep clean /etc/dnf/dnf.conf 
clean_requirements_on_remove=1 

If "clean_requirements_on_remove" is not set to "1", "True", or "yes", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to remove all software components after updated versions have been installed.

Set the "clean_requirements_on_remove" option to "1" in the "/etc/dnf/dnf.conf" file:

clean_requirements_on_remove=1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000437-GPOS-00194'
  tag gid: 'V-274185'
  tag rid: 'SV-274185r1120543_rule'
  tag stig_id: 'AZLX-23-002615'
  tag fix_id: 'F-78181r1120542_fix'
  tag cci: ['CCI-002617']
  tag nist: ['SI-2 (6)']
  tag 'host'
  tag 'container'

  describe parse_config_file('/etc/dnf/dnf.conf') do
    its('main.clean_requirements_on_remove') { should match(/1|True|yes/i) }
  end
end
