# encoding: UTF-8

control 'V-102521' do
  title 'Access to JMX management interface must be restricted.'
  desc  "Java Management Extensions (JMX) is used to provide programmatic
access to Tomcat for management purposes. This includes monitoring and control
of java applications running on Tomcat. If network access to the JMX port is
not restricted, attackers can gain access to the application used to manage the
system."
  desc  'rationale', ''
  desc  'check', "
    Review the system security plan and network documentation. Identify the
management networks that are used for system management.

    From the Tomcat server as a privileged user, run the following command:

    sudo grep -i jmxremote /etc/systemd/system/tomcat.service
    sudo ps -ef |grep -i jmxremote

    If there are no results, the JMX process is not being used, and this is not
a finding.

    If output includes jmxremote information, review the
-Dcom.sun.management.jmxremote.host setting.

    Compare the IP address associated with the JMX process with the network
information in the SSP. Ensure the IP address space is dedicated for system
management purposes.

    If the IP address that is associated with the JMX process is not dedicated
to system management usage, this is a finding.

    If jmxremote is in use but the host IP address is not specified, this is a
finding.
  "
  desc  'fix', "
    Make an operational determination regarding the use of JMX. If JMX
management is decided upon, identify the management networks that are used for
system management. Update the system security plan and network documentation
with the information.

    Edit the /etc/systemd/system/tomcat.service file.

    Add or modify the existing CATALINA_OPTS
-Dcom.sun.management.jmxremote.host setting. Set the host parameter to an IP
address that is only available on a management network.

    EXAMPLE:
    CATALINA_OPTS='-Dcom.sun.management.jmxremote.host=192.168.0.150'

    Restart Tomcat:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload

    Verify jmxmanagement access is restricted to the management network IP
address range.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000211-AS-000146'
  tag gid: 'V-102521'
  tag rid: 'SV-111461r1_rule'
  tag stig_id: 'TCAT-AS-000780'
  tag fix_id: 'F-108053r1_fix'
  tag cci: ['CCI-001082']
  tag nist: ['SC-2']

  describe "Compare the IP address associated with the JMX process with the network information in the SSP." do
    skip "Review the System Security Plan. Ensure the IP address space is dedicated for system management purposes. If the IP address that is associated with the JMX process 
    is not dedicated to system management usage, this is a finding."
  end

end

