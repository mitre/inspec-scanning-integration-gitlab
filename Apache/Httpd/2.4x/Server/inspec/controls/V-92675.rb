# encoding: UTF-8

control 'V-92675' do
  title "The Apache web server must separate the hosted applications from
hosted Apache web server management functionality."
  desc  "The separation of user functionality from web server management can be
accomplished by moving management functions to a separate IP address or port.
To further separate the management functions, separate authentication methods
and certificates should be used.

    By moving the management functionality, the possibility of accidental
discovery of the management functions by non-privileged users during hosted
application use is minimized.
  "
  desc  'rationale', ''
  desc  'check', "
    Review the web server documentation and deployed configuration to determine
whether hosted application functionality is separated from web server
management functions.

    If the functions are not separated, this is a finding.
  "
  desc  'fix', "Configure Apache to separate the hosted applications from web
server management functionality."
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-WSR-000129'
  tag gid: 'V-92675'
  tag rid: 'SV-102763r1_rule'
  tag stig_id: 'AS24-U1-000450'
  tag fix_id: 'F-98917r1_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe "The Apache web server must separate the hosted applications from hosted Apache web server management functionality." do 
    skip "Review the web server documentation and deployed configuration to determine whether hosted application functionality is separated from web server management functions.
    If the functions are not separated, this is a finding."
  end
  
end

