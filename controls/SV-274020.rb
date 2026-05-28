control 'SV-274020' do
  title 'Amazon Linux 2023 must have the rsyslog package installed.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis allow the organization to identify and respond to potential incidents in a proficient manner. If Amazon Linux 2023 does not provide the ability to centrally review Amazon Linux 2023 logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system has multiple logging components writing to different locations or systems.

To support the centralized capability, Amazon Linux 2023 must be able to provide the information in a format that can be extracted and used, allowing the application performing the centralization of the log records to meet this requirement.'
  desc 'check', 'Verify Amazon Linux 2023 is configured to collect system failure events with the following command: 
 
$ dnf list --installed rsyslog
Installed Packages
rsyslog.x86_64          8.2204.0-3.amzn2023.0.4          @amazonlinux
 
If the "rsyslog" package is not installed, this is a finding. 
 
Check that the log service is enabled with the following command: 
 
systemctl is-enabled rsyslog
enabled
 
If the command above returns "disabled", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to monitor all remote access methods by installing rsyslog with the following command:

$ sudo dnf install -y rsyslog

Enable the log service with the following command: 
 
$ sudo systemctl enable --now rsyslog'
  impact 0.5
  tag check_id: 'C-78111r1193303_chk'
  tag severity: 'medium'
  tag gid: 'V-274020'
  tag rid: 'SV-274020r1193303_rule'
  tag stig_id: 'AZLX-23-001040'
  tag gtitle: 'SRG-OS-000051-GPOS-00024'
  tag fix_id: 'F-78016r1120047_fix'
  tag 'documentable'
  tag cci: ['CCI-000154', 'CCI-001851']
  tag nist: ['AU-6 (4)', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('rsyslog') do
    it { should be_installed }
  end

  describe service('rsyslog') do
    it { should be_enabled }
  end
end
