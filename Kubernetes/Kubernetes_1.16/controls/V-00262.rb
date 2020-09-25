# encoding: UTF-8

control 'V-00262' do
    title 'The application must install security-relevant firmware updates within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
    desc  "Security flaws with firmware are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant firmware updates. Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 
	Organization-defined time periods for updating security-relevant firmware may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 
	This requirement will apply to software patch management solutions that are used to install firmware patches across the enclave (e.g., mobile device management solutions). Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant firmware updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.
	The application will be configured to check for and install security-relevant firmware updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000457'
    tag gid: 'V-00262'
    tag rid: ''
    tag stig_id: 'SRG-APP-000457'
    tag fix_id: ''
    tag cci: ['CCI-002607']
    tag nist: ['SI-2 c']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Hardware maintenance falls outside the Kubernetes scope.'
    end
end