# encoding: UTF-8

control 'TCAT-AS-000940' do
  title 'ErrorReportValve showReport must be set to false.'
  desc  'The Error Report Valve is a simple error handler for HTTP status codes
  that will generate and return HTML error pages. It can also be configured to
  return pre-defined static HTML pages for specific status codes and/or exception
  types. Disabling showReport will result in no error message or stack trace
  being send to the client. This setting can be tailored on a per-application
  basis within each application specific web.xml.'
  desc  'rationale', ''
  desc  'check', '
    As an elevated user on the Tomcat server run the following command:

    sudo grep -i ErrorReportValve $CATALINA_HOME\\conf\\server.xml file.

    If the \'org.apache.catalina.valves.ErrorReportValve\' className is not
  defined, or if showReport is set to \'false\', this is a finding.

    EXAMPLE:
    <Host ...>
      ...
      <Valve className=\'org.apache.catalina.valves.ErrorReportValve\'
  showReport=\'false\'/>
      ...
    </Host>
  '
  desc  'fix', '
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_HOME/conf/server.xml file.

    Create or modify the ErrorReportValve <Valve> element nested beneath each
  $Host element, define the ErrorReportValve className, and set
  \'showReport=false\'.

    EXAMPLE:
    <Host name=\'localhost\'  appBase=\'webapps\'
                unpackWARs=\'true\' autoDeploy=\'false\'>
    ...
    <Valve className=\'org.apache.catalina.valves.ErrorReportValve\'
    showReport=\'false\' />

    </Host>

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000267-AS-000170'
  tag gid: 'TCAT-AS-000940'
  tag rid: 'TCAT-AS-000940_rule'
  tag stig_id: 'TCAT-AS-000940'
  tag fix_id: 'F-TCAT-AS-000940_fix'
  tag cci: ['CCI-001314']
  tag nist: ['SI-11 b']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    valves = tomcat_server_file["//Valve/@className"]

    if valves.include?("org.apache.catalina.valves.ErrorReportValve")
      valves.each do |valve|
        if valve == "org.apache.catalina.valves.ErrorReportValve"
          describe tomcat_server_file["//Valve/@showReport"] do 
            it { should cmp "false" }
          end
        end
      end
    else
      describe valves do 
        it { should include "org.apache.catalina.valves.ErrorReportValve" }
      end
    end
      
end