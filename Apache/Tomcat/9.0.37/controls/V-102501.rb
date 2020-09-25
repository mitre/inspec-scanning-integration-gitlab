# encoding: UTF-8

control 'V-102501' do
  title 'Tomcat default ROOT web application must be removed.'
  desc  "The default ROOT web application includes the version of Tomcat that
is being used, links to Tomcat documentation, examples, FAQs, and mailing
lists. The default ROOT web application must be removed from a publicly
accessible Tomcat instance and a more appropriate default page shown to users.
It is acceptable to replace the contents of default ROOT with a new default web
application.

    WARNING: Removing the ROOT folder without replacing the content with valid
web based content will result in an error page being displayed to the browser
when the browser lands on the default page.
  "
  desc  'rationale', ''
  desc  'check', "
    From the Tomcat server OS type the following command:

    sudo ls -l $CATALINA_BASE/webapps/ROOT

    Review the index.jsp file. Also review the RELEASE-NOTES.txt file. Look for
content that describes the application as being licensed by the Apache Software
Foundation. Check the index.jsp for other verbiage that indicates the
application is part of the Tomcat server. Alternatively, use a web browser and
access the default web application and determine if the website application in
the ROOT folder is provided with the Apache Tomcat server.

    If the ROOT web application contains Tomcat default application content,
this is a finding.
  "
  desc  'fix', "
    WARNING: Removing the ROOT folder without replacing the content with valid
web based content will result in an error page being displayed to the browser
when the browser lands on the default page.

    From the Tomcat server OS:

    Either remove the files contained in $CATALINA_BASE/webapps/ROOT folder or
replace the content of the folder with a new application that serves as the new
default server application.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-APP-000141-AS-000095'
  tag gid: 'V-102501'
  tag rid: 'SV-111443r1_rule'
  tag stig_id: 'TCAT-AS-000570'
  tag fix_id: 'F-108035r2_fix'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']

  describe "Review the contents inside ROOT directory" do 
    skip "The ROOT directory contains default info check the index.jsp and RELEASE-NOTES.txt file for appropriate information that will be shown to users."
  end

end

