# encoding: UTF-8

control 'V-00049' do
    title 'The application must allow only the IAM (or individuals or roles appointed by the IAM) to select which auditable events are to be audited.'
    desc  "Without the capability to restrict which roles and individuals can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident, or identify those responsible for one. 
    The list of audited events is the set of events for which audits are to be generated. This set of events is typically a subset of the list of all events for which the system is capable of generating audit records."
    desc  'rationale', ''
    desc  'check', ""
    desc  'fix', ""
    impact 0.5
    tag severity: 'medium'
    tag gtitle: 'SRG-APP-000090'
    tag gid: 'V-00049'
    tag rid: ''
    tag stig_id: 'SRG-APP-000090'
    tag fix_id: ''
    tag cci: ['CCI-000171']
    tag nist: ['AU-12 b']

    describe 'This check is Not Applicable.' do
      skip 'Not Applicable: User account management provided outside kubernetes control plane.  This control is Out of scope.'
    end
end