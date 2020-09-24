# encoding: UTF-8

control 'V-00327' do
    title 'The application that provides a Simple Network Management Protocol (SNMP) Network Management System (NMS) must configure SNMPv3 to use FIPS-validated Advanced Encryption Standard (AES) cipher block algorithm to implement a bidirectional, cryptographically based authentication mechanism.'
    desc  "SNMPv3 supports commercial-grade security, including authentication, authorization, access control, and privacy while previous versions of the protocol contained well-known security weaknesses that were easily exploited. SNMPv3 can be configured for identification and cryptographically based authentication. 
	A typical SNMP implementation includes three components: managed device, SNMP agent, and NMS. The SNMP agent is the SNMP process that resides on the managed device and communicates with the network management system. The NMS is a combination of hardware and software that is used to monitor and administer a network. The SNMP data is stored in a highly structured, hierarchical format known as a management information base (MIB). The SNMP manager collects information about network connectivity, activity, and events by polling managed devices.
	SNMPv3 defines a user-based security model (USM) and a view-based access control model (VACM). SNMPv3 USM provides data integrity, data origin authentication, message replay protection, and protection against disclosure of the message payload. SNMPv3 VACM provides access control to determine whether a specific type of access (read or write) to the management information is allowed. Implement both VACM and USM for full protection.
	SNMPv3 server services must not be configured on products whose primary purpose is not to provide SNMP services. SNMP client services may be configured on the network element, application, or operating system to allow limited monitoring or querying of the device from by an SNMP server for management purposes. SNMP of any version will not be used to make configuration changes to the device. SNMPv3 must be disabled by default and enabled only if used. SNMP v3 provides security feature enhancements to SNMP, including encryption and message authentication. 
	Currently, the AES cipher block algorithm can be used for both applying cryptographic protection (e.g., encryption) and removing or verifying the protection that was previously applied (e.g., decryption) in DoD. The use of FIPS-approved algorithms for both cryptographic mechanisms is required. If any version of SNMP is used for remote administration, default SNMP community strings such as �public� and �private� should be removed before real community strings are put in place. If the defaults are not removed, an attacker could retrieve real community strings from the device using the default string."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000575'
    tag gid: 'V-00327'
    tag rid: ''
    tag stig_id: 'SRG-APP-000575'
    tag fix_id: ''
    tag cci: ['CCI-001967']
    tag nist: ['IA-3 (1)']

    describe 'This check is Not Applicable.' do
        skip 'Not Applicable: SNMP management provided outside Kubernetes scope.'
    end
end