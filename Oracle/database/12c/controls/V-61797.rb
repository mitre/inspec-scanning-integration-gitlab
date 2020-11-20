control 'V-61797' do
  title "The DBMS must notify appropriate individuals when accounts are
  created."
  desc "Once an attacker establishes initial access to a system, they often
  attempt to create a persistent method of re-establishing access. One way to
  accomplish this is for the attacker to simply create a new account.

      Notification of account creation is one method and best practice for
  mitigating this risk. A comprehensive account management process will ensure an
  audit trail which documents the creation of application user accounts and
  notifies administrators and/or application owners exist. Such a process greatly
  reduces the risk that accounts will be surreptitiously created and provides
  logging that can be used for forensic purposes.

      Note that user authentication and account management must be done via an
  enterprise-wide mechanism whenever possible.  Examples of enterprise-level
  authentication/access mechanisms include, but are not limited to, Active
  Directory and LDAP.  This requirement applies to cases where accounts are
  directly managed by Oracle.

      Notwithstanding how accounts are normally managed, the DBMS must support
  the requirement to notify appropriate individuals upon account creation within
  Oracle.  Indeed, in a configuration where accounts are managed externally, the
  creation of an account within Oracle may indicate hostile activity.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000291-DB-000139'
  tag "gid": 'V-61797'
  tag "rid": 'SV-76287r2_rule'
  tag "stig_id": 'O121-C2-020400'
  tag "fix_id": 'F-67713r1_fix'
  tag "cci": ['CCI-001683']
  tag "nist": ['AC-2 (4)', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Check DBMS settings to determine whether it will notify
  appropriate individuals when accounts are created.

  If the DBMS does not notify appropriate individuals when accounts are created,
  this is a finding."
  tag "fix": "Working with the DBA and site management, determine the
  appropriate individuals (by job role) to be notified.

  If Oracle Audit Vault is available, configure it to notify the appropriate
  individuals when accounts are created.

  If Oracle Audit Vault is not available, configure the Oracle DBMS's auditing
  feature to record account-creation activity.

  If Standard Auditing is used:
  Create and deploy a mechanism, such as a frequently-run job, to monitor the
  SYS.AUD$ table for these records and notify the appropriate individuals.

  If unified Auditing is used:
  Create and deploy a mechanism, such as a frequently-run job, to monitor the
  SYS.UNIFIED_AUDIT_TRAIL view for these records and notify the appropriate
  individuals."
  describe 'A manual review is required to ensure the DBMS notifies the appropriate individuals when accounts are
    created' do
    skip 'A manual review is required to ensure the DBMS notifies the appropriate individuals when accounts are
    created'
  end
end
