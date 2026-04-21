control 'SV-274152' do
  title 'Amazon Linux 2023 must enable the SELinux targeted policy.'
  desc 'Setting the SELinux policy to "targeted" or a more specialized policy ensures the system will confine processes that are likely to be targeted for exploitation, such as network or system services.

Note: During the development or debugging of SELinux modules, it is common to temporarily place nonproduction systems in "permissive" mode. In such temporary cases, SELinux policies should be developed, and once work is completed, the system should be reconfigured to "targeted".'
  desc 'check', 'Verify Amazon Linux 2023 SELINUX is using the targeted policy with the following command:

$ sestatus | grep policy
Loaded policy name: targeted

If the loaded policy name is not "targeted", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to use the targeted SELINUX policy.

Edit the file "/etc/selinux/config" and add or modify the following line:

 SELINUXTYPE=targeted 

A reboot is required for the changes to take effect.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000445-GPOS-00199'
  tag gid: 'V-274152'
  tag rid: 'SV-274152r1120738_rule'
  tag stig_id: 'AZLX-23-002445'
  tag fix_id: 'F-78148r1120737_fix'
  tag cci: ['CCI-002696']
  tag nist: ['SI-6 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe selinux do
    it { should_not be_disabled }
    it { should be_enforcing }
    its('policy') { should eq 'targeted' }
  end

  describe parse_config_file('/etc/selinux/config') do
    its('SELINUXTYPE') { should eq 'targeted' }
  end
end
