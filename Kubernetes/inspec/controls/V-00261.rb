# encoding: UTF-8

control 'V-00261' do
    title 'The application must install security-relevant software updates within the time period directed by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs).'
    desc  "Security flaws with software applications are discovered daily. Vendors are constantly updating and patching their products to address newly discovered security vulnerabilities. Organizations (including any contractor to the organization) are required to promptly install security-relevant software updates (e.g., patches, service packs, and hot fixes). Flaws discovered during security assessments, continuous monitoring, incident response activities, or information system error handling must also be addressed expeditiously. 
	Organization-defined time periods for updating security-relevant software may vary based on a variety of factors including, for example, the security category of the information system or the criticality of the update (i.e., severity of the vulnerability related to the discovered flaw). 
	This requirement will apply to software patch management solutions that are used to install patches across the enclave and also to applications themselves that are not part of that patch management solution. For example, many browsers today provide the capability to install their own patch software. Patch criticality, as well as system criticality will vary. Therefore, the tactical situations regarding the patch management process will also vary. This means that the time period utilized must be a configurable parameter. Time frames for application of security-relevant software updates may be dependent upon the Information Assurance Vulnerability Management (IAVM) process.
	The application will be configured to check for and install security-relevant software updates within an identified time period from the availability of the update. The specific time period will be defined by an authoritative source (e.g. IAVM, CTOs, DTMs, and STIGs)."
    desc  'rationale', ''
    desc  'check', "Authenticate on the Kubernetes Master Node.  Run the command:
	kubectl version --short
	If kubectl version has a setting not supporting Kubernetes skew policy , this is a finding.
    Kubernetes Skew Policy: https://kubernetes.io/docs/setup/release/version-skew-policy/#supported-versions"
    desc  'fix', "Upgrade Kubernetes to the supported version.  Institute and adhere to the policies and procedures to ensure that patches are consistently applied within the time allowed."
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000456'
    tag gid: 'V-00261'
    tag rid: ''
    tag stig_id: 'SRG-APP-000456'
    tag fix_id: ''
    tag cci: ['CCI-002605']
    tag nist: ['SI-2 c']

    kubectlGetVersion = command("kubectl version --short").stdout
    
    describe 'This test can only be performed by manual examination.' do
        skip "Manual Check: If kubectl version has a setting not supporting Kubernetes skew policy , this is a finding. Kubectl Version is:\n #{kubectlGetVersion}"
    end
end