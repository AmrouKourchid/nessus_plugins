#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The package checks in this plugin were extracted from
# SUSE update advisory SUSE-SU-2023:3536-1. The text itself
# is copyright (C) SUSE.
##

include('compat.inc');

if (description)
{
  script_id(180537);
  script_version("1.0");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/09/06");

  script_cve_id("CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842");
  script_xref(name:"SuSE", value:"SUSE-SU-2023:3536-1");

  script_name(english:"SUSE SLES15 / openSUSE 15 Security Update : docker (SUSE-SU-2023:3536-1)");

  script_set_attribute(attribute:"synopsis", value:
"The remote SUSE host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote SUSE Linux SLES15 / SLES_SAP15 / openSUSE 15 host has packages installed that are affected by multiple
vulnerabilities as referenced in the SUSE-SU-2023:3536-1 advisory.

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

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1210797");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1212368");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213120");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213229");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1213500");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214107");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214108");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.suse.com/1214109");
  # https://lists.suse.com/pipermail/sle-security-updates/2023-September/016100.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?274711fc");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28840");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28841");
  script_set_attribute(attribute:"see_also", value:"https://www.suse.com/security/cve/CVE-2023-28842");
  script_set_attribute(attribute:"solution", value:
"Update the affected docker, docker-bash-completion, docker-fish-completion and / or docker-zsh-completion packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28840");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2023/09/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-bash-completion");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:docker-fish-completion");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SuSE Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include('rpm.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item("Host/SuSE/release");
if (isnull(os_release) || os_release !~ "^(SLED|SLES|SUSE)") audit(AUDIT_OS_NOT, "SUSE / openSUSE");
var os_ver = pregmatch(pattern: "^(SLE(S|D)(?:_SAP)?\d+|SUSE([\d.]+))", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'SUSE / openSUSE');
os_ver = os_ver[1];
if (! preg(pattern:"^(SLES15|SLES_SAP15|SUSE15\.4|SUSE15\.5)$", string:os_ver)) audit(AUDIT_OS_NOT, 'SUSE SLES15 / SLES_SAP15 / openSUSE 15', 'SUSE / openSUSE (' + os_ver + ')');

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'SUSE / openSUSE (' + os_ver + ')', cpu);

var service_pack = get_kb_item("Host/SuSE/patchlevel");
if (isnull(service_pack)) service_pack = "0";
if (os_ver == "SLES15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES15 SP1/2/3/4/5", os_ver + " SP" + service_pack);
if (os_ver == "SLES_SAP15" && (! preg(pattern:"^(1|2|3|4|5)$", string:service_pack))) audit(AUDIT_OS_NOT, "SLES_SAP15 SP1/2/3/4/5", os_ver + " SP" + service_pack);

var pkgs = [
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'1', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.1']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'2', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.2']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'docker-fish-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'4', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.4']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'5', 'release':'SLES_SAP15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLES_SAP-release-15.5']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'docker-fish-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-ESPOS-release-3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'1', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'1', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.1', 'sles-ltss-release-15.1']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'2', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'2', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.2', 'sles-ltss-release-15.2']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'cpu':'aarch64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'cpu':'x86_64', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'docker-fish-completion-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-LTSS-release-15.3', 'sles-ltss-release-15.3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-containers-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'4', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.4', 'SUSE-Manager-Proxy-release-4.3', 'SUSE-Manager-Server-release-4.3', 'sle-module-containers-release-15.4', 'sles-release-15.4', 'suse-manager-server-release-4.3']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'sp':'5', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['SLE_HPC-release-15.5', 'sle-module-containers-release-15.5', 'sles-release-15.5']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'docker-fish-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'docker-zsh-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.4', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.4']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'docker-bash-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'docker-fish-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'docker-zsh-completion-24.0.5_ce-150000.185.1', 'release':'SUSE15.5', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['openSUSE-release-15.5']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'1', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.1']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'2', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.2']},
    {'reference':'docker-24.0.5_ce-150000.185.1', 'sp':'3', 'release':'SLES15', 'rpm_spec_vers_cmp':TRUE, 'exists_check':['sles-ltss-release-15.3']}
];

var ltss_caveat_required = FALSE;
var flag = 0;
foreach var package_array ( pkgs ) {
  var reference = NULL;
  var _release = NULL;
  var sp = NULL;
  var _cpu = NULL;
  var exists_check = NULL;
  var rpm_spec_vers_cmp = NULL;
  if (!empty_or_null(package_array['reference'])) reference = package_array['reference'];
  if (!empty_or_null(package_array['release'])) _release = package_array['release'];
  if (!empty_or_null(package_array['sp'])) sp = package_array['sp'];
  if (!empty_or_null(package_array['cpu'])) _cpu = package_array['cpu'];
  if (!empty_or_null(package_array['exists_check'])) exists_check = package_array['exists_check'];
  if (!empty_or_null(package_array['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = package_array['rpm_spec_vers_cmp'];
  if (reference && _release) {
    if (exists_check) {
      var check_flag = 0;
      foreach var check (exists_check) {
        if (!rpm_exists(release:_release, rpm:check)) continue;
        if ('ltss' >< tolower(check)) ltss_caveat_required = TRUE;
        check_flag++;
      }
      if (!check_flag) continue;
    }
    if (rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, rpm_spec_vers_cmp:rpm_spec_vers_cmp)) flag++;
  }
}

if (flag)
{
  var ltss_plugin_caveat = NULL;
  if(ltss_caveat_required) ltss_plugin_caveat = '\n' +
    'NOTE: This vulnerability check contains fixes that apply to\n' +
    'packages only available in SUSE Enterprise Linux Server LTSS\n' +
    'repositories. Access to these package security updates require\n' +
    'a paid SUSE LTSS subscription.\n';
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : rpm_report_get() + ltss_plugin_caveat
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'docker / docker-bash-completion / docker-fish-completion / etc');
}
