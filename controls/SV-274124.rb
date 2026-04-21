control 'SV-274124' do
  title 'Amazon Linux 2023 library directories must be owned by root.'
  desc 'If Amazon Linux 2023 were to allow any user to make changes to software libraries, then those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to operating systems with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs which execute with escalated privileges. Only qualified and authorized individuals shall be allowed to obtain access to information system components for purposes of initiating changes, including upgrades and modifications.'
  desc 'check', %q(Verify Amazon Linux 2023 systemwide shared library directories are owned by "root" with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \;

If any systemwide shared library directory is not owned by root, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 systemwide shared library directories within (/lib, /lib64, /usr/lib and /usr/lib64) to be protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory not owned by "root".

$ sudo chown root [DIRECTORY]'
  impact 0.5
  tag check_id: 'C-78215r1120358_chk'
  tag severity: 'medium'
  tag gid: 'V-274124'
  tag rid: 'SV-274124r1120360_rule'
  tag stig_id: 'AZLX-23-002305'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-78120r1120359_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  non_root_owned_libs = input('system_libraries').reject { |lib| file(lib).owned_by?('root') }

  describe 'System libraries' do
    it 'should be owned by root' do
      fail_msg = "Libs not owned by root:\n\t- #{non_root_owned_libs.join("\n\t- ")}"
      expect(non_root_owned_libs).to be_empty, fail_msg
    end
  end
end
