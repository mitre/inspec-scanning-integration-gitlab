control 'V-81907' do
  title "MongoDB must provide a warning to appropriate support staff when
  allocated audit record storage volume reaches 75% of maximum audit record
  storage capacity."
  desc  "Organizations are required to use a central log management system, so,
  under normal conditions, the audit space allocated to MongoDB on its own server
  will not be an issue. However, space will still be required on MongoDB server
  for audit records in transit, and, under abnormal conditions, this could fill
  up. Since a requirement exists to halt processing upon audit failure, a service
  outage would result.

  If support personnel are not notified immediately upon storage volume
  utilization reaching 75%, they are unable to plan for storage capacity
  expansion.

  The appropriate support staff include, at a minimum, the ISSO and the
  DBA/SA.
  "
  impact 0.5
  tag "gtitle": 'SRG-APP-000359-DB-000319'
  tag "gid": 'V-81907'
  tag "rid": 'SV-96621r1_rule'
  tag "stig_id": 'MD3X-00-000630'
  tag "fix_id": 'F-88757r2_fix'
  tag "cci": ['CCI-001855']
  tag "nist": ['AU-5 (1)', 'Rev_4']
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
  tag "check": "A MongoDB audit log that is configured to be stored in a file
  is identified in the MongoDB configuration file (default: /etc/mongod.conf)
  under the \"auditLog:\" key and subkey \"destination:\" where \"destination\"
  is \"file\".

  If this is the case then the \"AuditLog:\" subkey \"path:\" determines where
  (device/directory) that file will be located.

  View the mongodb configuration file (default location: /etc/mongod.conf) and
  identify how the \"auditlog.destination\" is configured.

  When the \"auditlog.destination\" is \"file\", this is a finding."
  tag "fix": "View the mongodb configuration file (default location:
  /etc/mongod.conf) and view the \"auditlog.path\" to identify the storage volume.

  Install MongoDB Ops Manager or other organization approved monitoring software.

  Configure the required alert in the monitoring software to send an alert where
  storage volume holding the auditLog file utilization reaches 75%."
  describe yaml(attribute('mongod_conf')) do
    its(%w{auditLog destination}) { should_not cmp 'file' }
  end
end
