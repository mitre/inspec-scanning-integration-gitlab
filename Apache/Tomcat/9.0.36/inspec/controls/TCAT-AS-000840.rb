# encoding: UTF-8

control 'TCAT-AS-000840' do
    title 'Secured connectors must use FIPS 140-2-validated cipher algorithms.'
    desc  'The HTTP protocol is not session oriented so application servers will
    use session IDs to track application user sessions. Unique session IDs address
    man-in-the-middle attacks, including session hijacking or insertion of false
    information into a session. If the attacker is unable to identify or guess the
    session information related to pending application traffic, they will have more
    difficulty in hijacking the session or otherwise manipulating valid sessions.'
    desc  'rationale', ''
    desc  'check', '
      From the Tomcat server console, run the following command:
  
      sudo grep -i fipsmode $CATALINA_HOME/conf/server.xml.
  
      If there are no results displayed or if FIPSMode is not set to
    FIPSMode=\'on\', this is a finding.
    '
    desc  'fix', '
      From the Tomcat server as a privileged user:
  
      sudo nano $CATALINA_HOME/conf/server.xml.
  
      In the <Listener/> element, locate the AprLifecycleListener, either add or
    modify the FIPSMode setting and set it to FIPSMode=\'on\'.
  
      EXAMPLE:
      <Listener
          className=\'org.apache.catalina.core.AprLifecycleListener\'
          SSLEngine=\'on\'
          FIPSMode=\'on\'
      />
  
      Restart the Tomcat server:
      sudo systemctl restart tomcat
      sudo systemctl daemon-reload
    '
    impact 0.3
    tag severity: 'low'
    tag gtitle: 'SRG-APP-000224-AS-000152'
    tag gid: 'TCAT-AS-000840'
    tag rid: 'TCAT-AS-000840_rule'
    tag stig_id: 'TCAT-AS-000840'
    tag fix_id: 'F-TCAT-AS-000840_fix'
    tag cci: ['CCI-001188']
    tag nist: ['SC-23 (3)']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    listeners = tomcat_server_file["//Listener/@className"]
    index = 0

    if listeners.include? "org.apache.catalina.core.AprLifecycleListener"
        for i in 0..listeners.count
            if listeners[i] == "org.apache.catalina.core.AprLifecycleListener"
                break
            else
                index+=1
            end
        end
    end
    
    fips_mode = tomcat_server_file["//Listener[#{index}]/@FIPSMode"]
    if !fips_mode.empty?
        describe fips_mode do 
            it { should cmp "on" }
        end
    else 
        describe fips_mode.empty? do 
            it { should  cmp "false" }
        end
    end
  
end