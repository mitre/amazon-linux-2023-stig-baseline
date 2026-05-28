control 'SV-274077' do
  title 'Amazon Linux 2023 must authenticate the remote logging server for off-loading audit logs via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.'
  desc 'check', %q(Verify Amazon Linux 2023 authenticates the remote logging server for off-loading audit logs with the following command:

$ sudo grep -i '$ActionSendStreamDriverAuthMode' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 
/etc/rsyslog.conf:$ActionSendStreamDriverAuthMode x509/name 

If the value of the "$ActionSendStreamDriverAuthMode" option is not set to "x509/name" or the line is commented out, ask the system administrator (SA) to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the transfer of the audit logs being off-loaded to another system or media is encrypted, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to authenticate the remote logging server for off-loading audit logs by setting the following option in "/etc/rsyslog.conf" or "/etc/rsyslog.d/[customfile].conf":

$ActionSendStreamDriverAuthMode x509/name'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag gid: 'V-274077'
  tag rid: 'SV-274077r1120219_rule'
  tag stig_id: 'AZLX-23-002065'
  tag fix_id: 'F-78073r1120218_fix'
  tag cci: ['CCI-000366', 'CCI-000154', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-6 (4)', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  if input('alternative_logging_method').to_s.empty?
    rsyslog_directives = input('logging_conf_files')
      .select { |path| file(path).exist? }
      .flat_map { |path| file(path).content.lines }
      .map(&:chomp)
      .reject { |line| line.strip.empty? || line.strip.start_with?('#') }
      .join("\n")

    parsed_directives = parse_config(rsyslog_directives, assignment_regex: /^\s*(\$\S+)\s+(\S+)/)

    describe 'rsyslog $ActionSendStreamDriverAuthMode (remote-server authentication mode)' do
      subject { parsed_directives['$ActionSendStreamDriverAuthMode'] }
      it { should eq 'x509/name' }
    end
  else
    describe 'rsyslog audit log transport (manual review)' do
      skip "input('alternative_logging_method') is set to '#{input('alternative_logging_method')}'; ask the administrator to confirm how rsyslog authenticates the remote logging server."
    end
  end
end
