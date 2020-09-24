# encoding: UTF-8

control 'V-92627' do
  title "The Apache web server must use a logging mechanism that is configured
to alert the Information System Security Officer (ISSO) and System
Administrator (SA) in the event of a processing failure."
  desc  "Reviewing log data allows an investigator to recreate the path of an
attacker and to capture forensic data for later use. Log data is also essential
to SAs in their daily administrative duties on the hosted system or within the
hosted applications.

    If the logging system begins to fail, events will not be recorded.
Organizations must define logging failure events, at which time the application
or the logging mechanism the application uses will provide a warning to the
ISSO and SA at a minimum.


  "
  desc  'rationale', ''
  desc  'check', "
    Work with the SIEM administrator to determine if an alert is configured
when audit data is no longer received as expected.

    If there is no alert configured, this is a finding.
  "
  desc  'fix', "Work with the SIEM administrator to configure an alert when no
audit data is received from Apache based on the defined schedule of
connections."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000108-WSR-000166'
  tag satisfies: ['SRG-APP-000108-WSR-000166', 'SRG-APP-000359-WSR-000065']
  tag gid: 'V-92627'
  tag rid: 'SV-102715r1_rule'
  tag stig_id: 'AS24-U1-000160'
  tag fix_id: 'F-98869r1_fix'
  tag cci: ['CCI-000139', 'CCI-001855']
  tag nist: ['AU-5 a', 'AU-5 (1)']

  describe "Review server logging and alert configuration" do 
    skip "Work with the SIEM administrator to determine if an alert is configured when audit 
    data is no longer received as expected. If there is no alert configured, this is a finding."
  end
  
end

