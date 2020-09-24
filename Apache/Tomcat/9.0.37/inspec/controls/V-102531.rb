# encoding: UTF-8

control 'V-102531' do
  title 'Clusters must operate on a trusted network.'
  desc  "Operating a Tomcat cluster on an untrusted network creates potential
for unauthorized persons to view or manipulate cluster session traffic. When
operating a Tomcat cluster, care must be taken to isolate the cluster traffic
from untrusted sources. Options include using a private VLAN, VPN, or IPSEC
tunnel or by encrypting cluster traffic by using the EncryptInterceptor. The
EncryptInterceptor adds encryption to the channel messages carrying session
data between Tomcat cluster nodes.

    Place the $Cluster element inside either the $Engine container or the $Host
container.

    Placing it in the engine means supporting clustering in all virtual hosts
of Tomcat and sharing the messaging component. When the user places the
$Cluster inside the $Engine element, the cluster will append the host name of
each session manager to the manager's name so that two contexts with the same
name (but sitting inside two different hosts) will be distinguishable.
  "
  desc  'rationale', ''
  desc  'check', "
    Review System Security Plan (SSP) documentation determine if the Tomcat
server is part of an application server cluster. Also identify Tomcat network
interfaces and the proxy/load balancer that front-ends the cluster.

    From the Tomcat server as a privileged user, run the following command:

    sudo grep -i -A2 -B2 \"Cluster\" $CATALINA_BASE/conf/server.xml

    If the <Cluster/> element is commented out, or there are no results
returned, this requirement is NA.

    If a cluster is in use, run the following command as a privileged user:

    grep -i EncryptInterceptor $CATALINA_BASE/conf/server.xml file.

    If the Tomcat server is clustered and the EncryptionInterceptor is not in
use or if the cluster traffic is not on a private network or VLAN, this is a
finding.
  "
  desc  'fix', "
    Update the System Security Plan (SSP) and document the network interface,
their related IP addresses, and which interfaces transport Tomcat cluster
traffic. Also document which interface is multi-cast enabled if using the
McastService membership class versus Static.

    To obtain the information needed for the SSP:
    sudo grep -i -A3 \"<Membership className\" $CATALINA_BASE/conf.server.xml

    Document the address=\"<ipAddress>\" value.

    Review the OS routing tables. Identify and document which interface is
configured to route the Tomcat class D IP multicast traffic.

    sudo netstat -r

    END of Documentation instructions.

    From the Tomcat server as a privileged user, edit the
$CATALINA_BASE/conf/server.xml file.

    sudo nano $CATALINA_BASE/conf/server.xml

    Locate the <Interceptor/> element nested within the <Channel/> element.

    Add the <Interceptor className=\"org.apache.catalina.tribes.group.
    interceptors.EncryptInterceptor\"/> to the server.xml and save the file.

    Restart the Tomcat server:
    sudo systemctl restart tomcat

    NOTE:
    The EncryptInterceptor adds encryption to the channel messages carrying
session data between nodes. This feature was added in Tomcat 9.0.13. If using
the TcpFailureDetector interceptor, the EncryptInterceptor must be inserted
into the interceptor chain BEFORE the TcpFailureDetector. When validating
cluster members, TcpFailureDetector writes channel data directly to the other
members without using the remainder of the interceptor chain, but on the
receiving side, the message still goes through the chain (in reverse). Because
of this asymmetry, the EncryptInterceptor must execute before the
TcpFailureDetector on the sender and after it on the receiver; otherwise,
message corruption will occur.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000225-AS-000154'
  tag gid: 'V-102531'
  tag rid: 'SV-111471r1_rule'
  tag stig_id: 'TCAT-AS-000860'
  tag fix_id: 'F-108063r1_fix'
  tag cci: ['CCI-001190']
  tag nist: ['SC-24']

  describe "Review System Security Plan (SSP) documentation determine if the Tomcat server is part of an application server cluster." do 
    skip "If the server is part of a cluster identify Tomcat network interfaces and the proxy/load balancer that 
    front-ends the cluster. If the Tomcat server is clustered and the EncryptionInterceptor is not in
    use or if the cluster traffic is not on a private network or VLAN, this is a
    finding."
  end

end