# encoding: UTF-8

control 'V-102583' do
  title 'Changes to $CATALINA_HOME/lib/ folder must be logged.'
  desc  "The $CATALINA_HOME/lib folder contains library files for the Tomcat
Catalina server. These are in the form of java archive (jar) files. To provide
forensic evidence in the event of file tampering, changes to contents in this
folder must be logged. For Linux OS flavors other than Ubuntu, use the relevant
OS commands. This can be done on the Ubuntu OS via the auditctl command. Using
the -p wa flag set the permissions flag for a file system watch and logs file
attribute and content change events into syslog."
  desc  'rationale', ''
  desc  'check', "
    Run the following commands From the Tomcat server as a privileged user:

    Identify the home folder for the Tomcat server.

    sudo grep -i -- 'catalina_home\\|catalina_base'
/etc/systemd/system/tomcat.service

    Check the audit rules for the Tomcat folders

    sudo auditctl -l $CATALINA_HOME/bin |grep -i lib

    If the results do not include -w $CATALINA_HOME/lib -p wa -k tomcat, or if
there are no results, this is a finding.
  "
  desc  'fix', "
    From the Tomcat server as a privileged user, use the auditctl command.

    sudo auditctl  -w $CATALINA_HOME/lib -p wa -k tomcat

    Validate the audit watch was created.
    sudo auditctl -l

    The user should see:
    -w $CATALINA_HOME/ -p wa -k tomcat
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000504-AS-000229'
  tag gid: 'V-102583'
  tag rid: 'SV-111523r1_rule'
  tag stig_id: 'TCAT-AS-001592'
  tag fix_id: 'F-108115r1_fix'
  tag cci: ['CCI-000172']
  tag nist: ['AU-12 c']

  describe "Changes to content in $CATALINA_BASE/lib directory must be logged" do 
    skip "Check the audit rules for the Tomcat folders. If the results do not include 
    -w $CATALINA_HOME/lib -p wa -k tomcat, or if there are no results, this is a finding."
  end

end