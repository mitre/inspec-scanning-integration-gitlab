# encoding: UTF-8

control 'V-00157' do
    title 'The application must check the validity of all data inputs except those specifically identified by the organization.'
    desc  "Invalid user input occurs when a user inserts data or characters into an application's data entry fields and the application is unprepared to process that data. This results in unanticipated application behavior, potentially leading to an application or information system compromise. Invalid input is one of the primary methods employed when attempting to compromise an application. 
	Checking the valid syntax and semantics of information system inputs (e.g., character set, length, numerical range, and acceptable values) verifies that inputs match specified definitions for format and content. Software applications typically follow well-defined protocols that use structured messages (i.e., commands or queries) to communicate between software modules or system components. Structured messages can contain raw or unstructured data interspersed with metadata or control information. If software applications use attacker-supplied inputs to construct structured messages without properly encoding such messages, then the attacker could insert malicious commands or special characters that can cause the data to be interpreted as control information or metadata. Consequently, the module or component that receives the tainted output will perform the wrong operations or otherwise interpret the data incorrectly. Prescreening inputs prior to passing to interpreters prevents the content from being unintentionally interpreted as commands. Input validation helps to ensure accurate and correct inputs and prevent attacks such as cross-site scripting and a variety of injection attacks."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000251'
    tag gid: 'V-00157'
    tag rid: ''
    tag stig_id: 'SRG-APP-000251'
    tag fix_id: ''
    tag cci: ['CCI-001310']
    tag nist: ['SI-10']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Data input validation falls outside the Kubernetes scope.'
    end
end