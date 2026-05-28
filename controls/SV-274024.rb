control 'SV-274024' do
  title 'Amazon Linux 2023 must have the Advanced Intrusion Detection Environment (AIDE) package installed.'
  desc 'If security functions are not verified, they may not operate correctly and the failure may go unnoticed. Security function is defined as the hardware, software, and/or firmware of the information system responsible for enforcing the system security policy and supporting the isolation of code and data on which the protection is based. Security functionality includes, but is not limited to, establishing system accounts, configuring access authorizations (i.e., permissions, privileges), setting events to be audited, and setting intrusion detection parameters.'
  desc 'check', %q(Verify Amazon Linux 2023 has the AIDE package installed with the following command:

$ dnf list --installed aide
Installed Packages
aide.x86_64          0.18.6-1.amzn2023.0.1          @amazonlinux

If AIDE is not installed, ask the system administrator (SA) how file integrity checks are performed on the system. 

If there is no application installed to perform integrity checks, this is a finding.

If AIDE is installed, check if it has been initialized with the following command:

$ sudo /usr/sbin/aide --check

If the output is "Couldn't open file /var/lib/aide/aide.db.gz for reading", this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to have the AIDE package installed.

Install AIDE:

$ sudo dnf install -y aide

Initialize AIDE:
 
$ sudo /usr/sbin/aide --init

The new database must be renamed to be read by AIDE:

$ sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz

Perform a manual check:

$ sudo /usr/sbin/aide --check
Example output:

2023-06-05 10:16:08 -0600 (AIDE 0.16)
AIDE found NO differences between database and filesystem. Looks okay!!'
  impact 0.5
  tag check_id: 'C-78115r1120058_chk'
  tag severity: 'medium'
  tag gid: 'V-274024'
  tag rid: 'SV-274024r1190697_rule'
  tag stig_id: 'AZLX-23-001060'
  tag gtitle: 'SRG-OS-000363-GPOS-00150'
  tag fix_id: 'F-78020r1190696_fix'
  tag 'documentable'
  tag cci: ['CCI-002696', 'CCI-001744', 'CCI-001889']
  tag nist: ['SI-6 a', 'CM-3 (5)', 'AU-8 b']
  tag 'host'

  file_integrity_tool = input('file_integrity_tool')

  only_if('Control not applicable within a container', impact: 0.0) do
    !virtualization.system.eql?('docker')
  end

  describe package(file_integrity_tool) do
    it { should be_installed }
  end

  if file_integrity_tool == 'aide'
    # STIG check text: "If the output is 'Couldn't open file /var/lib/aide/aide.db.gz
    # for reading', this is a finding." — equivalent to verifying the AIDE database
    # has been initialized.
    describe 'AIDE database (/var/lib/aide/aide.db.gz)' do
      subject { file('/var/lib/aide/aide.db.gz') }
      it 'should exist (run "aide --init" + rename to aide.db.gz to initialize)' do
        expect(subject.exist?).to be(true), 'AIDE database not initialized. Run "sudo aide --init" then "sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz".'
      end
    end
  end
end
