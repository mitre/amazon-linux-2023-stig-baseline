control 'SV-274175' do
  title 'Amazon Linux 2023 must synchronize internal information system clocks to the authoritative time source at least every 24 hours.'
  desc 'Inaccurate time stamps make it more difficult to correlate events and can lead to an inaccurate analysis. Determining the correct time a particular event occurred on a system is critical when conducting forensic analysis and investigating system events. Sources outside the configured acceptable allowance (drift) may be inaccurate.

Synchronizing internal information system clocks provides uniformity of time stamps for information systems with multiple system clocks and systems connected over a network.

Depending on the infrastructure in use, the "pool" directive may not be supported.'
  desc 'check', 'Verify Amazon Linux 2023 chrony service specifies a maximum interval of 24 hours between requests sent to a United States Naval Observatory (USNO) server with the following command:

Note: <USNO/DOD Server> is used in place of a time source IP address.

$ sudo grep maxpoll /etc/chrony.conf
server <USNO/DOD Server> iburst maxpoll 16

If the "maxpoll" option is not configured, set to a number greater than 16, or the line is commented out, this is a finding.

Verify Amazon Linux 2023 chrony service is configured to use authoritative USNO or appropriate DOD time source with the following command:

$ sudo grep -i server /etc/chrony.conf
server <USNO/DOD Server>

If the parameter "server" is not set or is not set to an authoritative USNO/DOD time source, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to compare internal information system clocks at least every 24 hours with an NTP server. Ensure the following line is added or updated in "/etc/chrony.conf":

server <USNO/DOD Server> iburst maxpoll 16'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000356-GPOS-00144'
  tag satisfies: ['SRG-OS-000355-GPOS-00143', 'SRG-OS-000356-GPOS-00144', 'SRG-OS-000359-GPOS-00146', 'SRG-OS-000785-GPOS-00250']
  tag gid: 'V-274175'
  tag rid: 'SV-274175r1190705_rule'
  tag stig_id: 'AZLX-23-002565'
  tag fix_id: 'F-78171r1184034_fix'
  tag cci: ['CCI-001891', 'CCI-001890', 'CCI-002046', 'CCI-004926', 'CCI-004922', 'CCI-004923']
  tag nist: ['AU-8 (1) (a)', 'AU-8 b', 'AU-8 (1) (b)', 'SC-45 (1) (b)', 'SC-45', 'SC-45 (1) (a)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  chrony_conf = chrony_conf('/etc/chrony.conf')

  # Converts to array if only one value present
  time_sources = []
  time_sources = [chrony_conf.server].flatten if chrony_conf.server
  time_sources += [chrony_conf.pool].flatten if chrony_conf.pool  # PR #93 bug fix!

  unless time_sources.nil?
    max_poll_values = time_sources.map { |val|
      val.match?(/.*maxpoll.*/) ? val.gsub(/.*maxpoll\s+(\d+)(\s+.*|$)/, '\1').to_i : 10
    }
  end

  # Verify the "chrony.conf" file is configured to an authoritative DoD time source by running the following command:

  describe chrony_conf('/etc/chrony.conf') do
    its('server') { should_not be_nil }
  end

  authoritative_timeserver = input('authoritative_timeserver').to_s

  if authoritative_timeserver.empty?
    describe 'Authoritative time source match' do
      skip "Input 'authoritative_timeserver' is not set; skipping the server-name match. Provide a regex/substring identifying the org-approved USNO/DoD time source to enable this check."
    end
  elsif !chrony_conf('/etc/chrony.conf').server.nil?
    if chrony_conf('/etc/chrony.conf').server.is_a? String
      describe chrony_conf('/etc/chrony.conf') do
        its('server') { should match authoritative_timeserver }
      end
    end

    if chrony_conf('/etc/chrony.conf').server.is_a? Array
      describe chrony_conf('/etc/chrony.conf') do
        its('server.join') { should match authoritative_timeserver }
      end
    end
  end
  # All time sources must contain valid maxpoll entries
  unless time_sources.nil?
    describe 'chronyd maxpoll values (99=maxpoll absent)' do
      subject { max_poll_values }
      it { should all be < 17 }
    end
  end
end
