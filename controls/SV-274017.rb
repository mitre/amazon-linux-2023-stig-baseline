control 'SV-274017' do
  title 'Amazon Linux 2023 must have the audit package installed.'
  desc 'Successful incident response and auditing relies on timely, accurate system information and analysis to allow the organization to identify and respond to potential incidents in a proficient manner. If Amazon Linux 2023 does not provide the ability to centrally review Amazon Linux 2023 logs, forensic analysis is negatively impacted.

Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system has multiple logging components writing to different locations or systems.

To support the centralized capability, Amazon Linux 2023 must be able to provide the information in a format that can be extracted and used, allowing the application performing the centralization of the log records to meet this requirement.'
  desc 'check', 'Verify Amazon Linux 2023 has the audit package installed with the following command:

$ dnf list --installed audit
Installed Packages
audit.x86_64          3.0.6-1.amzn2023.0.2          @System
 
If the "audit" package is not installed, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 so that the audit service to produce audit records containing the information needed to establish when (date and time) an event occurred.

Install the audit service (if the audit service is not already installed) with the following command:

$ sudo dnf install -y audit'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000062-GPOS-00031'
  tag satisfies: ['SRG-OS-000062-GPOS-00031', 'SRG-OS-000037-GPOS-00015', 'SRG-OS-000038-GPOS-00016', 'SRG-OS-000039-GPOS-00017', 'SRG-OS-000040-GPOS-00018', 'SRG-OS-000041-GPOS-00019', 'SRG-OS-000042-GPOS-00021', 'SRG-OS-000051-GPOS-00024', 'SRG-OS-000054-GPOS-00025', 'SRG-OS-000122-GPOS-00063', 'SRG-OS-000254-GPOS-00095', 'SRG-OS-000255-GPOS-00096', 'SRG-OS-000337-GPOS-00129', 'SRG-OS-000348-GPOS-00136', 'SRG-OS-000349-GPOS-00137', 'SRG-OS-000350-GPOS-00138', 'SRG-OS-000351-GPOS-00139', 'SRG-OS-000352-GPOS-00140', 'SRG-OS-000353-GPOS-00141', 'SRG-OS-000354-GPOS-00142', 'SRG-OS-000358-GPOS-00145', 'SRG-OS-000365-GPOS-00152', 'SRG-OS-000392-GPOS-00172', 'SRG-OS-000475-GPOS-00220', 'SRG-OS-000055-GPOS-00026']
  tag gid: 'V-274017'
  tag rid: 'SV-274017r1120039_rule'
  tag stig_id: 'AZLX-23-001025'
  tag fix_id: 'F-78013r1120038_fix'
  tag cci: ['CCI-000169', 'CCI-000130', 'CCI-000131', 'CCI-000132', 'CCI-000133', 'CCI-000134', 'CCI-000135', 'CCI-000154', 'CCI-000158', 'CCI-000159', 'CCI-000172', 'CCI-001464', 'CCI-001487', 'CCI-001814', 'CCI-001875', 'CCI-001876', 'CCI-001877', 'CCI-001878', 'CCI-001879', 'CCI-001880', 'CCI-001881', 'CCI-001882', 'CCI-001889', 'CCI-001914', 'CCI-002884', 'CCI-003938']
  tag nist: ['AU-12 a', 'AU-3 a', 'AU-3 b', 'AU-3 c', 'AU-3 d', 'AU-3 e', 'AU-3 (1)', 'AU-6 (4)', 'AU-7 (1)', 'AU-8 a', 'AU-12 c', 'AU-14 (1)', 'AU-3 f', 'CM-5 (1)', 'AU-7 a', 'AU-7 b', 'AU-8 b', 'AU-12 (3)', 'MA-4 (1) (a)', 'CM-5 (1) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe package('audit') do
    it { should be_installed }
  end
end
