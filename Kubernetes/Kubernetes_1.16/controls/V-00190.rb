# encoding: UTF-8

control 'V-00190' do
  title 'The application must prevent organization-defined software from executing at higher privilege levels than users executing the software.'
  desc  "In certain situations, software applications/programs need to execute with elevated privileges to perform required functions. However, if the privileges required for execution are at a higher level than the privileges assigned to organizational users invoking such applications/programs, those users are indirectly provided with greater privileges than assigned by organizations."
  desc  'rationale', ''
  desc  'check', "On the Master Node, run the command:
	kubectl get podsecuritypolicy
	For any pod security policies listed, edit the policy  with the command:
	kubectl edit podsecuritypolicy policyname
  Where policyname is the name of the policy
	Review the runAsUser, supplementalGroups and fsGroup sections of the policy.
	If any of these sections are missing, this is a finding.
	If the rule within the runAsUser section is not set to MustRunAsNonRoot, this is a finding.
	If the ranges within the supplementalGroups section has min set to 0 or min is missing, this is a finding.
	If the ranges within the fsGroup section has a min set to 0 or the min is missing, this is a finding.
	"
  desc  'fix', "From the Master node, save the following policy to a file called restricted.yml
	apiVersion: policy/v1beta1
  kind: PodSecurityPolicy
  metadata:
  name: restricted
  annotations:
    seccomp.security.alpha.kubernetes.io/allowedProfileNames: 'docker/default,runtime/default'
    apparmor.security.beta.kubernetes.io/allowedProfileNames: 'runtime/default'
    seccomp.security.alpha.kubernetes.io/defaultProfileName:  'runtime/default'
    apparmor.security.beta.kubernetes.io/defaultProfileName:  'runtime/default'
  spec:
  privileged: false
  # Required to prevent escalations to root.
  allowPrivilegeEscalation: false
  # This is redundant with non-root + disallow privilege escalation,
  # but we can provide it for defense in depth.
  requiredDropCapabilities:
    - ALL
  # Allow core volume types.
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    # Assume that persistentVolumes set up by the cluster admin are safe to use.
    - 'persistentVolumeClaim'
  hostNetwork: false
  hostIPC: false
  hostPID: false
  runAsUser:
    # Require the container to run without root privileges.
    rule: 'MustRunAsNonRoot'
  seLinux:
    # This policy assumes the nodes are using AppArmor rather than SELinux.
    rule: 'RunAsAny'
  supplementalGroups:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  fsGroup:
    rule: 'MustRunAs'
    ranges:
      # Forbid adding the root group.
      - min: 1
        max: 65535
  readOnlyRootFilesystem: false
	To implement the policy, run the command:
	kubectl create -f restricted.yml"
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000342'
  tag gid: 'V-00190'
  tag rid: ''
  tag stig_id: 'SRG-APP-000342'
  tag fix_id: ''
  tag cci: ['CCI-002233']
  tag nist: ['AC-6 (8)']

  describe 'This test can only be performed by manual examination.' do
    skip 'Manual Check: Please check STIG for command reference.'
  end
end