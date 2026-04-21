control 'SV-274120' do
  title 'Amazon Linux 2023 library directories must have mode "755" or less permissive.'
  desc 'If Amazon Linux 2023 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', 'Verify Amazon Linux 2023 systemwide shared library directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec ls -l {} \\;

If any systemwide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 systemwide shared library directories (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access. 

Run the following command, replacing "[DIRECTORY]" with any library directory with a mode more permissive than "755".

$ sudo chmod 755 [DIRECTORY]'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag gid: 'V-274120'
  tag rid: 'SV-274120r1120348_rule'
  tag stig_id: 'AZLX-23-002285'
  tag fix_id: 'F-78116r1120347_fix'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  mode_for_libs = input('mode_for_libs')

  overly_permissive_libs = input('system_libraries').select { |lib|
    file(lib).more_permissive_than?(mode_for_libs)
  }

  describe 'System libraries' do
    it "should not have modes set higher than #{mode_for_libs}" do
      fail_msg = "Overly permissive system libraries:\n\t- #{overly_permissive_libs.join("\n\t- ")}"
      expect(overly_permissive_libs).to be_empty, fail_msg
    end
  end
end
