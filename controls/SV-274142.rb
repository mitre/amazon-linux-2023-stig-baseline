control 'SV-274142' do
  title 'Amazon Linux 2023 must automatically exit interactive command shell user sessions after 15 minutes of inactivity.'
  desc 'Terminating an idle interactive command shell user session within a short time period reduces the window of opportunity for unauthorized personnel to take control of it when left unattended in a virtual terminal or physical console.'
  desc 'check', %q(Verify Amazon Linux 2023 is configured to exit interactive command shell user sessions after 10 minutes of inactivity or less with the following command:

$ sudo grep -i tmout /etc/profile /etc/profile.d/*.sh
/etc/profile.d/tmout.sh:declare -xr TMOUT=600

If "TMOUT" is not set to "600" or less in a script located in the "/etc/'profile.d/ directory, is missing or is commented out, this is a finding.)
  desc 'fix', 'Configure Amazon Linux 2023 to exit interactive command shell user sessions after 10 minutes of inactivity.

Add or edit the following line in "/etc/profile.d/tmout.sh":

#!/bin/bash

declare -xr TMOUT=600'
  impact 0.5
  tag check_id: 'C-78233r1120412_chk'
  tag severity: 'medium'
  tag gid: 'V-274142'
  tag rid: 'SV-274142r1120414_rule'
  tag stig_id: 'AZLX-23-002396'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-78138r1120413_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000029-GPOS-00010']
  tag 'documentable'
  tag cci: ['CCI-000057', 'CCI-001133']
  tag nist: ['AC-11 a', 'SC-10']
  tag 'host'
  tag 'container'

  tmout_cmd = command('grep -i tmout /etc/profile /etc/profile.d/*.sh')

  # Guard clause for command failure
  unless tmout_cmd.exit_status == 0
    describe 'Shell timeout configuration' do
      it 'should have TMOUT configured' do
        expect(tmout_cmd.exit_status).to eq(0), 'No TMOUT configuration found in profile files'
      end
    end
  end

  # Parse TMOUT value with better error handling
  tmout_match = tmout_cmd.stdout.match(/^[^#]+TMOUT\s*=\s*(\d+)/i)

  describe 'Shell timeout configuration' do
    it 'should have TMOUT configured' do
      expect(tmout_match).to_not be_nil, 'No valid TMOUT value found in profile files'
    end

    if tmout_match
      it 'should have appropriate timeout value' do
        actual_timeout = tmout_match[1].to_i
        expect(actual_timeout).to be <= input('shell_session_timeout'),
          "TMOUT is #{actual_timeout}, should be <= #{input('shell_session_timeout')}"
      end
    end
  end
end
