control 'SV-273998' do
  title 'Amazon Linux 2023 must have GPG signature verification enabled for all software repositories.'
  desc 'Changes to any software components can have significant effects on the overall security of Amazon Linux 2023. This requirement ensures the software has not been tampered with and that it has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor. This verifies the software has not been tampered with and that it has been provided by a trusted vendor.'
  desc 'check', 'Verify Amazon Linux 2023 software repositories enforce a signature check on the packages prior to allowing installation with the following command:

$ grep -w gpgcheck /etc/yum.repos.d/*.repo | more
/etc/yum.repos.d/amazonlinux.repo:gpgcheck=1
/etc/yum.repos.d/amazonlinux.repo:gpgcheck=1
/etc/yum.repos.d/amazonlinux.repo:gpgcheck=1
/etc/yum.repos.d/kernel-livepatch.repo:gpgcheck=1
/etc/yum.repos.d/kernel-livepatch.repo:gpgcheck=1

If any repository has "gpgcheck=0" or "False", or if the option is commented out, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to verify the signature of packages from a repository prior to installation by setting the following option in the "/etc/yum.repos.d/[your_repo_name].repo" file:

gpgcheck=1'
  impact 0.7
  tag check_id: 'C-78089r1119980_chk'
  tag severity: 'high'
  tag gid: 'V-273998'
  tag rid: 'SV-273998r1119982_rule'
  tag stig_id: 'AZLX-23-000125'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-77994r1119981_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  repo_def_files = command('ls /etc/yum.repos.d/*.repo').stdout.split("\n")

  if repo_def_files.empty?
    describe 'No repos found in /etc/yum.repos.d/*.repo' do
      skip 'No repos found in /etc/yum.repos.d/*.repo'
    end
  else
    # pull out all repo definitions from all files into one big hash
    repos = repo_def_files.map { |file| parse_config_file(file).params }.inject(&:merge)

    # check big hash for repos that fail the test condition
    failing_repos = repos.keys.reject { |repo_name| repos[repo_name]['gpgcheck'] == '1' }

    describe 'All repositories' do
      it 'should be configured to verify digital signatures' do
        expect(failing_repos).to be_empty, "Misconfigured repositories:\n\t- #{failing_repos.join("\n\t- ")}"
      end
    end
  end
end
