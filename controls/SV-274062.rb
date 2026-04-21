control 'SV-274062' do
  title 'Amazon Linux 2023 must prohibit the use of cached authenticators after one day.'
  desc 'If cached authentication information is out-of-date, the validity of the authentication information may be questionable.'
  desc 'check', 'Verify Amazon Linux 2023 is configured so that the System Security Services Daemon (SSSD) prohibits the use of cached authentications after one day.

Note: Cached authentication settings should be configured even if smart card authentication is not used on the system.

Check that SSSD allows cached authentications with the following command:

$ sudo grep -ir cache_credentials /etc/sssd/sssd.conf /etc/sssd/conf.d/
/etc/sssd/sssd.conf:cache_credentials = true

If "cache_credentials" is set to "false" or missing from the configuration file, this is not a finding and no further checks are required.

If "cache_credentials" is set to "true", check that SSSD prohibits the use of cached authentications after one day with the following command:

$ sudo grep -ir offline_credentials_expiration /etc/sssd/sssd.conf /etc/sssd/conf.d/
/etc/sssd/sssd.conf:offline_credentials_expiration = 1

If "offline_credentials_expiration" is not set to a value of "1", this is a finding.'
  desc 'fix', 'Configure Amazon Linux 2023 SSSD service to prohibit the use of cached authentications after one day.

Add or change the following line in "/etc/sssd/sssd.conf" just below the line [pam]:

offline_credentials_expiration = 1'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000383-GPOS-00166'
  tag gid: 'V-274062'
  tag rid: 'SV-274062r1120174_rule'
  tag stig_id: 'AZLX-23-001305'
  tag fix_id: 'F-78058r1120173_fix'
  tag cci: ['CCI-002007']
  tag nist: ['IA-5 (13)']
  tag 'host'

  sssd_config = parse_config_file('/etc/sssd/sssd.conf')

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !virtualization.system.eql?('docker')
  }

  describe.one do
    describe 'Cache credentials enabled' do
      subject { sssd_config.content }
      it { should_not match(/cache_credentials\s*=\s*true/) }
    end
    describe 'Offline credentials expiration' do
      subject { sssd_config }
      its('pam.offline_credentials_expiration') { should cmp '1' }
    end
  end
end
