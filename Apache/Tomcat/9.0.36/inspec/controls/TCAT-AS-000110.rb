# encoding: UTF-8

control 'TCAT-AS-000110' do
    title 'The Java Security Manager must be enabled.'
    desc  'The Java SecurityManager is what allows a web browser to run an applet
    in its own sandbox to prevent untrusted code from accessing files on the local
    file system, connecting to a host other than the one the applet was loaded
    from, and so on. In the same way the SecurityManager protects the user from an
    untrusted applet running in the browser, use of a SecurityManager while running
    Tomcat can protect the server from trojan servlets, JSPs, JSP beans, tag
    libraries, or even inadvertent mistakes.'
    desc  'rationale', ''
    desc  'check', '
      Identify the tomcat systemd startup file which is usually called
    \'tomcat.service\' and can be viewed as a link in the /etc/systemd/system/
    folder.
  
      sudo cat /etc/systemd/system/tomcat.service |grep -i security
  
      If the ExecStart parameter does not include the -security flag, this is a
    finding.
    '
    desc  'fix', '
      As an admin user on the Tomcat server, modify the
    /etc/systemd/system/tomcat.service file and set the \'ExecStart\' parameter to
    read:
      \'ExecStart=/opt/tomcat/bin/startup.sh -security\'
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000033-AS-000024'
    tag gid: 'TCAT-AS-000110'
    tag rid: 'TCAT-AS-000110_rule'
    tag stig_id: 'TCAT-AS-000110'
    tag fix_id: 'F-TCAT-AS-000110_fix'
    tag cci: ['CCI-000213']
    tag nist: ['AC-3']
    
    tomcat_service_file = "/etc/systemd/system/tomcat.service"
    describe command("cat #{tomcat_service_file} | grep ExecStart | grep -security") do
        its('stdout') { should_not eq '' }
    end

end