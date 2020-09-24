# encoding: UTF-8

control 'V-92695' do
  title "The Apache web server must be built to fail to a known safe state if
system initialization fails, shutdown fails, or aborts fail."
  desc  "Determining a safe state for failure and weighing that against a
potential denial of service for users depends on what type of application the
web server is hosting. For an application presenting publicly available
information that is not critical, a safe state for failure might be to shut
down for any type of failure, but for an application that presents critical and
timely information, a shutdown might not be the best state for all failures.

    Performing a proper risk analysis of the hosted applications and
configuring the web server according to what actions to take for each failure
condition will provide a known fail safe state for the web server.


  "
  desc  'rationale', ''
  desc  'check', "
    Interview the System Administrator for the Apache 2.4 web server.

    Ask for documentation on the disaster recovery methods tested and planned
for the Apache 2.4 web server in the event of the necessity for rollback.

    If documentation for a disaster recovery has not been established, this is
a finding.
  "
  desc  'fix', "
    Prepare documentation for disaster recovery methods for the Apache 2.4 web
server in the event of the necessity for rollback.

    Document and test the disaster recovery methods designed.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-WSR-000140'
  tag satisfies: ['SRG-APP-000225-WSR-000140', 'SRG-APP-000225-WSR-000074']
  tag gid: 'V-92695'
  tag rid: 'SV-102783r1_rule'
  tag stig_id: 'AS24-U1-000550'
  tag fix_id: 'F-98937r1_fix'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  describe "Review documentation for a disaster recovery procedures" do 
    skip "Interview the System Administrator for the Apache 2.4 web server. Ask for documentation 
      on the disaster recovery methods tested and planned for the Apache 2.4 web server in the event of the necessity for rollback."
  end
  
end