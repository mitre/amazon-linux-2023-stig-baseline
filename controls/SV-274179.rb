control 'SV-274179' do
  title 'Amazon Linux 2023 must mount /dev/shm with the nodev option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that "/dev/shm" is mounted with the "nodev" option with the following command:

$ mount | grep /dev/shm
tmpfs on /dev/shm type tmpfs (rw,nodev,nosuid,noexec,seclabel)

If the /dev/shm file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that "/dev/shm" is mounted with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/dev/shm" file system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-274179'
  tag rid: 'SV-274179r1120525_rule'
  tag stig_id: 'AZLX-23-002585'
  tag fix_id: 'F-78175r1120524_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  path = '/dev/shm'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
