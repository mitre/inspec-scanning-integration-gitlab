# encoding: UTF-8

control 'V-00224' do
    title 'Before establishing a local, remote, and/or network connection with any endpoint device, the application must use a bidirectional authentication mechanism configured with a FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to authenticate with the device.'
    desc  "Without device-to-device authentication, communications with malicious devices may be established. Bidirectional authentication provides stronger safeguards to validate the identity of other devices for connections that are of greater risk. Currently, DoD requires the use of AES for bidirectional authentication since it is the only FIPS-validated AES cipher block algorithm. 
	For distributed architectures (e.g., service-oriented architectures), the decisions regarding the validation of authentication claims may be made by services separate from the services acting on those decisions. In such situations, it is necessary to provide authentication decisions (as opposed to the actual authenticators) to the services that need to act on those decisions.
	A local connection is any connection with a device communicating without the use of a network. A network connection is any connection with a device that communicates through a network (e.g., local area or wide area network; the Internet). A remote connection is any connection with a device communicating through an external network (e.g., the Internet).
	Because of the challenges of applying this requirement on a large scale, organizations are encouraged to apply the requirement only to those limited number (and type) of devices that truly need to support this capability."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000395'
    tag gid: 'V-00224'
    tag rid: ''
    tag stig_id: 'SRG-APP-000395'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network management provided outside Kubernetes scope.'
    end
end