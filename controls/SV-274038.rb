control 'SV-274038' do
  title 'Amazon Linux 2023 must have SSH installed.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.'
  desc 'check', 'Verify Amazon Linux 2023 has the openssh-server package installed with the following command:

$ dnf list --installed openssh-server
Installed Packages
openssh-server.x86_64          8.7p1-8.amzn2023.0.13          @amazonlinux

If the "openssh-server" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to have the openssh-server package installed with the following command:
 
$ sudo dnf install -y openssh-server'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000112-GPOS-00057'
  tag satisfies: ['SRG-OS-000423-GPOS-00187', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000425-GPOS-00189', 'SRG-OS-000426-GPOS-00190', 'SRG-OS-000112-GPOS-00057', 'SRG-OS-000113-GPOS-00058']
  tag gid: 'V-274038'
  tag rid: 'SV-274038r1120102_rule'
  tag stig_id: 'AZLX-23-001180'
  tag fix_id: 'F-78034r1120101_fix'
  tag cci: ['CCI-002418', 'CCI-002420', 'CCI-002421', 'CCI-002422', 'CCI-001941']
  tag nist: ['SC-8', 'SC-8 (2)', 'SC-8 (1)', 'IA-2 (8)']
  tag 'host'
  tag 'container-conditional'

  openssh_present = package('openssh-server').installed?

  only_if('This requirement is Not Applicable in a container without OpenSSH installed or when physical protections are employed', impact: 0.0) do
    !((virtualization.system.eql?('docker') && !openssh_present) || input('physical_protections_employed'))
  end

  if input('allow_container_openssh_server') == false
    describe 'In a container Environment' do
      it 'the OpenSSH Server should be installed only when allowed in a container environment' do
        expect(openssh_present).to eq(false), 'OpenSSH Server is installed but not approved for the container environment'
      end
    end
  else
    describe 'OpenSSH Server package' do
      it 'should be installed' do
        expect(package('openssh-server').installed?).to eq(true), 'OpenSSH Server is not installed'
      end
    end
  end
end
