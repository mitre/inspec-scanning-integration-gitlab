# encoding: UTF-8

control 'V-00063' do
    title 'The application must provide the capability to centrally review and analyze audit records from multiple components within the system.'
    desc  "Successful incident response and auditing relies on timely, accurate system information and analysis in order to allow the organization to identify and respond to potential incidents in a proficient manner. If the application does not provide the ability to centrally review the application logs, forensic analysis is negatively impacted. 
	Segregation of logging data to multiple disparate computer systems is counterproductive and makes log analysis and log event alarming difficult to implement and manage, particularly when the system or application has multiple logging components written to different locations or systems.
	Automated mechanisms for centralized reviews and analyses include, for example, Security Information Management products."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000111'
    tag gid: 'V-00063'
    tag rid: ''
    tag stig_id: 'SRG-APP-000111'
    tag fix_id: ''
    tag cci: ['CCI-000154']
    tag nist: ['AU-6 (4)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Central manage solution to review and analyze audit record is outside the scope of the Kubernetes Control Plane.'
    end
end