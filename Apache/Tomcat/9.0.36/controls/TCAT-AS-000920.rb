# encoding: UTF-8

control 'TCAT-AS-000920' do
  title 'ErrorReportValve showServerInfo must be set to false.'
  desc  'The Error Report Valve is a simple error handler for HTTP status codes
  that will generate and return HTML error pages. It can also be configured to
  return pre-defined static HTML pages for specific status codes and/or exception
  types. Disabling showServerInfo will only return the HTTP status code and
  remove all CSS from the default non-error related HTTP responses.'
  desc  'rationale', ''
  desc  'check', '
    As an elevated user on the Tomcat server run the following command:

    sudo grep -i ErrorReportValve $CATALINA_HOME\\conf\\server.xml file.

    If the ErrorReportValve element is not defined and showServerInfo set to
  \'false\', this is a finding.

    EXAMPLE:
    <Host ...>
      ...
      <Valve className=\'org.apache.catalina.valves.ErrorReportValve\'
  howServerInfo=\'false\'/>
      ...
    </Host>
  '
  desc  'fix', '
    As a privileged user on the Tomcat server:

    Edit the $CATALINA_HOME/conf/server.xml file.

    Create or modify an ErrorReportValve <Valve> element nested beneath each
  $Host element.

    EXAMPLE:
    <Host name=\'localhost\'  appBase=\'webapps\'
                unpackWARs=\'true\' autoDeploy=\'false\'>
    ...
    <Valve className=\'org.apache.catalina.valves.ErrorReportValve\'
    showServerInfo=\'false\' />
    ...
    </Host>

    Restart the Tomcat server:
    sudo systemctl restart tomcat
    sudo systemctl daemon-reload
  '
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-AS-000169'
  tag gid: 'TCAT-AS-000920'
  tag rid: 'TCAT-AS-000920_rule'
  tag stig_id: 'TCAT-AS-000920'
  tag fix_id: 'F-TCAT-AS-000920_fix'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

    tomcat_server_file = xml("/usr/local/tomcat/conf/server.xml")
    valves = tomcat_server_file["//Valve/@className"]

    if valves.include?("org.apache.catalina.valves.ErrorReportValve")
      valves.each do |valve|
        if valve == "org.apache.catalina.valves.ErrorReportValve"
          describe tomcat_server_file["//Valve/@showServerInfo"] do 
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