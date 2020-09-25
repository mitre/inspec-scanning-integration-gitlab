# encoding: UTF-8

control 'V-00156' do
    title 'Applications must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of Denial of Service (DoS) attacks.'
    desc  "DoS is a condition when a resource is not available for legitimate users. When this occurs, the organization either cannot accomplish its mission or must operate at degraded capacity. 
	In the case of application DoS attacks, care must be taken when designing the application to ensure the application makes the best use of system resources. SQL queries have the potential to consume large amounts of CPU cycles if they are not tuned for optimal performance. Web services containing complex calculations requiring large amounts of time to complete can bog down if too many requests for the service are encountered within a short period of time. 
	The methods employed to meet this requirement will vary depending upon the technology the application utilizes. However, a variety of technologies exist to limit or, in some cases, eliminate the effects of application related DoS attacks. Employing increased capacity and bandwidth combined with specialized application layer protection devices and service redundancy may reduce the susceptibility to some DoS attacks."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000247'
    tag gid: 'V-00156'
    tag rid: ''
    tag stig_id: 'SRG-APP-000247'
    tag fix_id: ''
    tag cci: ['CCI-001095']
    tag nist: ['SC-5 (2)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: Network bandwidth management is outside the Kubernetes scope.'
    end
end