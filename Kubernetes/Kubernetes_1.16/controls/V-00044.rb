# encoding: UTF-8

control 'V-00044' do
    title 'The publicly accessible application must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the application. '
    desc  "Display of a standardized and approved use notification before granting access to the publicly accessible application ensures privacy and security notification verbiage used is consistent with applicable federal laws, Executive Orders, directives, policies, regulations, standards, and guidance.
	System use notifications are required only for access via logon interfaces with human users and are not required when such human interfaces do not exist.
	The banner must be formatted in accordance with DTM-08-060. Use the following verbiage for desktops, laptops, and other devices accommodating banners of 1300 characters:
	\"You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.
	By using this IS (which includes any device attached to this IS), you consent to the following conditions:
	-The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.
	-At any time, the USG may inspect and seize data stored on this IS.
	-Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.
	-This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy.
	-Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.\"
 
    Use the following verbiage for operating systems that have severe limitations on the number of characters that can be displayed in the banner:
	\"I've read & consent to terms in IS user agreem't.\""
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000070'
    tag gid: 'V-00044'
    tag rid: ''
    tag stig_id: 'SRG-APP-000070'
    tag fix_id: ''
    tag cci: ['CCI-001384, CCI-001385, CCI-001386, CCI-001387, CCI-001388']
    tag nist: ['AC-8 c 1, AC-8 c 2, AC-8 c 3']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: The Kubernetes API Server will only have public access through a web application.  Any requirements for public access and the web application would be handled by web server requirements and application requirements.'
    end
end