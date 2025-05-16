#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225311);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-48910");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-48910");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net: ipv6: ensure we call
    ipv6_mc_down() at most once There are two reasons for addrconf_notify() to be called with NETDEV_DOWN:
    either the network device is actually going down, or IPv6 was disabled on the interface. If either of them
    stays down while the other is toggled, we repeatedly call the code for NETDEV_DOWN, including
    ipv6_mc_down(), while never calling the corresponding ipv6_mc_up() in between. This will cause a new entry
    in idev->mc_tomb to be allocated for each multicast group the interface is subscribed to, which in turn
    leaks one struct ifmcaddr6 per nontrivial multicast group the interface is subscribed to. The following
    reproducer will leak at least $n objects: ip addr add ff2e::4242/32 dev eth0 autojoin sysctl -w
    net.ipv6.conf.eth0.disable_ipv6=1 for i in $(seq 1 $n); do ip link set up eth0; ip link set down eth0 done
    Joining groups with IPV6_ADD_MEMBERSHIP (unprivileged) or setting the sysctl net.ipv6.conf.eth0.forwarding
    to 1 (=> subscribing to ff02::2) can also be used to create a nontrivial idev->mc_list, which will the
    leak objects with the right up-down-sequence. Based on both sources for NETDEV_DOWN events the interface
    IPv6 state should be considered: - not ready if the network interface is not ready OR IPv6 is disabled for
    it - ready if the network interface is ready AND IPv6 is enabled for it The functions ipv6_mc_up() and
    ipv6_down() should only be run when this state changes. Implement this by remembering when the IPv6 state
    is ready, and only run ipv6_mc_down() if it actually changed from ready to not ready. The other direction
    (not ready -> ready) already works correctly, as: - the interface notification triggered codepath for
    NETDEV_UP / NETDEV_CHANGE returns early if ipv6 is disabled, and - the disable_ipv6=0 triggered codepath
    skips fully initializing the interface as long as addrconf_link_ready(dev) returns false - calling
    ipv6_mc_up() repeatedly does not leak anything (CVE-2022-48910)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-48910");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/03/05");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/cpu", "Host/local_checks_enabled", "global_settings/vendor_unpatched");
  script_require_ports("Host/RedHat/release", "Host/RedHat/rpm-list");

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
     "kernel",
     "kernel-rt"
    ],
    "type": "rpm_package"
   },
   "check_algorithm": "rpm",
   "constraints": [
    {
     "requires": [
      {
       "scope": "target",
       "match": {
        "distro": "redhat"
       }
      },
      {
       "scope": "target",
       "match": {
        "os_version": "8"
       }
      }
     ]
    }
   ]
  }
 ]
};

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_WARNING);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
