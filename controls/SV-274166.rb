control 'SV-274166' do
  title 'Amazon Linux 2023 must terminate idle user sessions.'
  desc 'Terminating an idle session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle session will also free up resources committed by the managed network element. 

Terminating network connections associated with communications sessions includes, for example, de-allocating associated TCP/IP address/port pairs at Amazon Linux 2023 level, and de-allocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that Amazon Linux 2023 terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.'
  desc 'check', 'Verify Amazon Linux 2023 logs out sessions that are idle for 10 minutes with the following command:

$ sudo grep -i ^StopIdleSessionSec /etc/systemd/logind.conf

StopIdleSessionSec=600

If "StopIdleSessionSec" is not configured to "600" seconds, this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 to log out idle sessions by editing the /etc/systemd/logind.conf file with the following line:

StopIdleSessionSec=600

The "logind" service must be restarted for the changes to take effect. To restart the "logind" service, run the following command:

$ sudo systemctl restart systemd-logind'
  impact 0.5
  tag check_id: 'C-78257r1155168_chk'
  tag severity: 'medium'
  tag gid: 'V-274166'
  tag rid: 'SV-274166r1155170_rule'
  tag stig_id: 'AZLX-23-002510'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-78162r1155169_fix'
  tag 'documentable'
  tag cci: ['CCI-001133']
  tag nist: ['SC-10']
  tag 'container'
  tag 'host'

  stop_idle_session_sec = input('stop_idle_session_sec')

  describe parse_config_file('/etc/systemd/logind.conf') do
    its('Login') { should include('StopIdleSessionSec' => stop_idle_session_sec.to_s) }
  end
end
