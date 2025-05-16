#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225932);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-28840");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-28840");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

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

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-28840");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2023/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/Debian/dpkg-l", "Host/Debian/release");

  exit(0);
}
include('vdf.inc');

# @tvdl-content
var vuln_data = {
 "metadata": {
  "spec_version": "1.0p"
 },
 "requires": [
  {
   "scope": "scan_config",
   "match": {
    "vendor_unpatched": true
   }
  },
  {
   "scope": "target",
   "match": {
    "os": "linux"
   }
  }
 ],
 "report": {
  "report_type": "unpatched"
 },
 "checks": [
  {
   "product": {
    "name": [
     "docker-doc",
     "docker.io",
     "golang-github-docker-docker-dev"
    ],
    "type": "dpkg_package"
   },
   "check_algorithm": "dpkg",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "debian"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "11"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
