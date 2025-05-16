#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(225533);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2022-49198");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2022-49198");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: Fix crash due to
    tcp_tsorted_anchor was initialized before release skb Got crash when doing pressure test of mptcp:
    =========================================================================== dst_release:
    dst:ffffa06ce6e5c058 refcnt:-1 kernel tried to execute NX-protected page - exploit attempt? (uid: 0) BUG:
    unable to handle kernel paging request at ffffa06ce6e5c058 PGD 190a01067 P4D 190a01067 PUD 43fffb067 PMD
    22e403063 PTE 8000000226e5c063 Oops: 0011 [#1] SMP PTI CPU: 7 PID: 7823 Comm: kworker/7:0 Kdump: loaded
    Tainted: G E Hardware name: QEMU Standard PC (i440FX + PIIX, 1996), BIOS 1.2.1 04/01/2014 Call Trace: ?
    skb_release_head_state+0x68/0x100 ? skb_release_all+0xe/0x30 ? kfree_skb+0x32/0xa0 ?
    mptcp_sendmsg_frag+0x57e/0x750 ? __mptcp_retrans+0x21b/0x3c0 ? __switch_to_asm+0x35/0x70 ?
    mptcp_worker+0x25e/0x320 ? process_one_work+0x1a7/0x360 ? worker_thread+0x30/0x390 ?
    create_worker+0x1a0/0x1a0 ? kthread+0x112/0x130 ? kthread_flush_work_fn+0x10/0x10 ?
    ret_from_fork+0x35/0x40 =========================================================================== In
    __mptcp_alloc_tx_skb skb was allocated and skb->tcp_tsorted_anchor will be initialized, in under memory
    pressure situation sk_wmem_schedule will return false and then kfree_skb. In this case skb->_skb_refdst is
    not null because_skb_refdst and tcp_tsorted_anchor are stored in the same mem, and kfree_skb will try to
    release dst and cause crash. (CVE-2022-49198)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2022-49198");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2025/02/26");
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
        "os_version": "9"
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
