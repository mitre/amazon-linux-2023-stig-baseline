control 'SV-274177' do
  title 'Amazon Linux 2023 must prevent the loading of a new kernel for later execution.'
  desc 'Changes to any software components can have significant effects on the overall security of Amazon Linux 2023. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to disable kernel image loading.

Check the status of the kernel.kexec_load_disabled kernel parameter with the following command:

$ sudo sysctl kernel.kexec_load_disabled
kernel.kexec_load_disabled = 1

If "kernel.kexec_load_disabled" is not set to "1" or is missing, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to disable kernel image loading.

Add or edit the following line in a system configuration file in the "/etc/sysctl.d/" directory:

kernel.kexec_load_disabled = 1

Load settings from all system configuration files with the following command:

$ sudo sysctl --system'
  impact 0.5
  tag check_id: 'C-78268r1120517_chk'
  tag severity: 'medium'
  tag gid: 'V-274177'
  tag rid: 'SV-274177r1120519_rule'
  tag stig_id: 'AZLX-23-002575'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-78173r1120518_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  describe kernel_parameter('kernel.kexec_load_disabled') do
    its('value') { should cmp 1 }
  end
end
