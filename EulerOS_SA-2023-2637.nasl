#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(188692);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/01/16");

  script_cve_id("CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842");

  script_name(english:"EulerOS 2.0 SP11 : docker-engine (EulerOS-SA-2023-2637)");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the docker-engine package installed, the EulerOS installation on the remote host is
affected by the following vulnerabilities :

  - Moby is an open source container framework developed by Docker Inc. that is distributed as Docker,
    Mirantis Container Runtime, and various other downstream projects/products. The Moby daemon component
    (`dockerd`), which is developed as moby/moby, is commonly referred to as *Docker*. Swarm Mode, which is
    compiled in and delivered by default in dockerd and is thus present in most major Moby downstreams, is a
    simple, built-in container orchestrator that is implemented through a combination of SwarmKit and
    supporting network code. The overlay network driver is a core feature of Swarm Mode, providing isolated
    virtual LANs that allow communication between containers and services across the cluster. This driver is
    an implementation/user of VXLAN, which encapsulates link-layer (Ethernet) frames in UDP datagrams that tag
    the frame with a VXLAN Network ID (VNI) that identifies the originating overlay network. In addition, the
    overlay network driver supports an optional, off-by-default encrypted mode, which is especially useful
    when VXLAN packets traverses an untrusted network between nodes. Encrypted overlay networks function by
    encapsulating the VXLAN datagrams through the use of the IPsec Encapsulating Security Payload protocol in
    Transport mode. By deploying IPSec encapsulation, encrypted overlay networks gain the additional
    properties of source authentication through cryptographic proof, data integrity through check-summing, and
    confidentiality through encryption. When setting an endpoint up on an encrypted overlay network, Moby
    installs three iptables (Linux kernel firewall) rules that enforce both incoming and outgoing IPSec. These
    rules rely on the u32 iptables extension provided by the xt_u32 kernel module to directly filter on a
    VXLAN packet's VNI field, so that IPSec guarantees can be enforced on encrypted overlay networks without
    interfering with other overlay networks or other users of VXLAN. Two iptables rules serve to filter
    incoming VXLAN datagrams with a VNI that corresponds to an encrypted network and discards unencrypted
    datagrams. The rules are appended to the end of the INPUT filter chain, following any rules that have been
    previously set by the system administrator. Administrator-set rules take precedence over the rules Moby
    sets to discard unencrypted VXLAN datagrams, which can potentially admit unencrypted datagrams that should
    have been discarded. The injection of arbitrary Ethernet frames can enable a Denial of Service attack. A
    sophisticated attacker may be able to establish a UDP or TCP connection by way of the container's outbound
    gateway that would otherwise be blocked by a stateful firewall, or carry out other escalations beyond
    simple injection by smuggling packets into the overlay network. Patches are available in Moby releases
    23.0.3 and 20.10.24. As Mirantis Container Runtime's 20.10 releases are numbered differently, users of
    that platform should update to 20.10.16. Some workarounds are available. Close the VXLAN port (by default,
    UDP port 4789) to incoming traffic at the Internet boundary to prevent all VXLAN packet injection, and/or
    ensure that the `xt_u32` kernel module is available on all nodes of the Swarm cluster. (CVE-2023-28840)

  - Moby is an open source container framework developed by Docker Inc. that is distributed as Docker,
    Mirantis Container Runtime, and various other downstream projects/products. The Moby daemon component
    (`dockerd`), which is developed as moby/moby is commonly referred to as *Docker*. Swarm Mode, which is
    compiled in and delivered by default in `dockerd` and is thus present in most major Moby downstreams, is a
    simple, built-in container orchestrator that is implemented through a combination of SwarmKit and
    supporting network code. The `overlay` network driver is a core feature of Swarm Mode, providing isolated
    virtual LANs that allow communication between containers and services across the cluster. This driver is
    an implementation/user of VXLAN, which encapsulates link-layer (Ethernet) frames in UDP datagrams that tag
    the frame with the VXLAN metadata, including a VXLAN Network ID (VNI) that identifies the originating
    overlay network. In addition, the overlay network driver supports an optional, off-by-default encrypted
    mode, which is especially useful when VXLAN packets traverses an untrusted network between nodes.
    Encrypted overlay networks function by encapsulating the VXLAN datagrams through the use of the IPsec
    Encapsulating Security Payload protocol in Transport mode. By deploying IPSec encapsulation, encrypted
    overlay networks gain the additional properties of source authentication through cryptographic proof, data
    integrity through check-summing, and confidentiality through encryption. When setting an endpoint up on an
    encrypted overlay network, Moby installs three iptables (Linux kernel firewall) rules that enforce both
    incoming and outgoing IPSec. These rules rely on the `u32` iptables extension provided by the `xt_u32`
    kernel module to directly filter on a VXLAN packet's VNI field, so that IPSec guarantees can be enforced
    on encrypted overlay networks without interfering with other overlay networks or other users of VXLAN. An
    iptables rule designates outgoing VXLAN datagrams with a VNI that corresponds to an encrypted overlay
    network for IPsec encapsulation. Encrypted overlay networks on affected platforms silently transmit
    unencrypted data. As a result, `overlay` networks may appear to be functional, passing traffic as
    expected, but without any of the expected confidentiality or data integrity guarantees. It is possible for
    an attacker sitting in a trusted position on the network to read all of the application traffic that is
    moving across the overlay network, resulting in unexpected secrets or user data disclosure. Thus, because
    many database protocols, internal APIs, etc. are not protected by a second layer of encryption, a user may
    use Swarm encrypted overlay networks to provide confidentiality, which due to this vulnerability this is
    no longer guaranteed. Patches are available in Moby releases 23.0.3, and 20.10.24. As Mirantis Container
    Runtime's 20.10 releases are numbered differently, users of that platform should update to 20.10.16. Some
    workarounds are available. Close the VXLAN port (by default, UDP port 4789) to outgoing traffic at the
    Internet boundary in order to prevent unintentionally leaking unencrypted traffic over the Internet,
    and/or ensure that the `xt_u32` kernel module is available on all nodes of the Swarm cluster.
    (CVE-2023-28841)

  - Moby) is an open source container framework developed by Docker Inc. that is distributed as Docker,
    Mirantis Container Runtime, and various other downstream projects/products. The Moby daemon component
    (`dockerd`), which is developed as moby/moby is commonly referred to as *Docker*. Swarm Mode, which is
    compiled in and delivered by default in `dockerd` and is thus present in most major Moby downstreams, is a
    simple, built-in container orchestrator that is implemented through a combination of SwarmKit and
    supporting network code. The `overlay` network driver is a core feature of Swarm Mode, providing isolated
    virtual LANs that allow communication between containers and services across the cluster. This driver is
    an implementation/user of VXLAN, which encapsulates link-layer (Ethernet) frames in UDP datagrams that tag
    the frame with the VXLAN metadata, including a VXLAN Network ID (VNI) that identifies the originating
    overlay network. In addition, the overlay network driver supports an optional, off-by-default encrypted
    mode, which is especially useful when VXLAN packets traverses an untrusted network between nodes.
    Encrypted overlay networks function by encapsulating the VXLAN datagrams through the use of the IPsec
    Encapsulating Security Payload protocol in Transport mode. By deploying IPSec encapsulation, encrypted
    overlay networks gain the additional properties of source authentication through cryptographic proof, data
    integrity through check-summing, and confidentiality through encryption. When setting an endpoint up on an
    encrypted overlay network, Moby installs three iptables (Linux kernel firewall) rules that enforce both
    incoming and outgoing IPSec. These rules rely on the `u32` iptables extension provided by the `xt_u32`
    kernel module to directly filter on a VXLAN packet's VNI field, so that IPSec guarantees can be enforced
    on encrypted overlay networks without interfering with other overlay networks or other users of VXLAN. The
    `overlay` driver dynamically and lazily defines the kernel configuration for the VXLAN network on each
    node as containers are attached and detached. Routes and encryption parameters are only defined for
    destination nodes that participate in the network. The iptables rules that prevent encrypted overlay
    networks from accepting unencrypted packets are not created until a peer is available with which to
    communicate. Encrypted overlay networks silently accept cleartext VXLAN datagrams that are tagged with the
    VNI of an encrypted overlay network. As a result, it is possible to inject arbitrary Ethernet frames into
    the encrypted overlay network by encapsulating them in VXLAN datagrams. The implications of this can be
    quite dire, and GHSA-vwm3-crmr-xfxw should be referenced for a deeper exploration. Patches are available
    in Moby releases 23.0.3, and 20.10.24. As Mirantis Container Runtime's 20.10 releases are numbered
    differently, users of that platform should update to 20.10.16. Some workarounds are available. In multi-
    node clusters, deploy a global pause' container for each encrypted overlay network, on every node. For a
    single-node cluster, do not use overlay networks of any sort. Bridge networks provide the same
    connectivity on a single node and have no multi-node features. The Swarm ingress feature is implemented
    using an overlay network, but can be disabled by publishing ports in `host` mode instead of `ingress` mode
    (allowing the use of an external load balancer), and removing the `ingress` network. If encrypted overlay
    networks are in exclusive use, block UDP port 4789 from traffic that has not been validated by IPSec.
    (CVE-2023-28842)

Note that Tenable Network Security has extracted the preceding description block directly from the EulerOS security
advisory. Tenable has attempted to automatically clean and format it as much as possible without introducing additional
issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2023-2637
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3ecd891e");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker-engine packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28840");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/01/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:docker-engine");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

var _release = get_kb_item("Host/EulerOS/release");
if (isnull(_release) || _release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
var uvp = get_kb_item("Host/EulerOS/uvp_version");
if (_release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

var sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(11)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11");

if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP11", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu && "x86" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

var flag = 0;

var pkgs = [
  "docker-engine-18.09.0-300.h37.38.33.eulerosv2r11"
];

foreach (var pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"11", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "docker-engine");
}
