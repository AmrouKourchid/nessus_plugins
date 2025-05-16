#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(227356);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52906");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52906");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: net/sched: act_mpls: Fix warning
    during failed attribute validation The 'TCA_MPLS_LABEL' attribute is of 'NLA_U32' type, but has a
    validation type of 'NLA_VALIDATE_FUNCTION'. This is an invalid combination according to the comment above
    'struct nla_policy':  Meaning of `validate' field, use via NLA_POLICY_VALIDATE_FN: NLA_BINARY Validation
    function called for the attribute. All other Unused - but note that it's a union  This can trigger the
    warning [1] in nla_get_range_unsigned() when validation of the attribute fails. Despite being of 'NLA_U32'
    type, the associated 'min'/'max' fields in the policy are negative as they are aliased by the 'validate'
    field. Fix by changing the attribute type to 'NLA_BINARY' which is consistent with the above comment and
    all other users of NLA_POLICY_VALIDATE_FN(). As a result, move the length validation to the validation
    function. No regressions in MPLS tests: # ./tdc.py -f tc-tests/actions/mpls.json [...] # echo $? 0 [1]
    WARNING: CPU: 0 PID: 17743 at lib/nlattr.c:118 nla_get_range_unsigned+0x1d8/0x1e0 lib/nlattr.c:117 Modules
    linked in: CPU: 0 PID: 17743 Comm: syz-executor.0 Not tainted 6.1.0-rc8 #3 Hardware name: QEMU Standard PC
    (i440FX + PIIX, 1996), BIOS rel-1.13.0-48-gd9c812dda519-prebuilt.qemu.org 04/01/2014 RIP:
    0010:nla_get_range_unsigned+0x1d8/0x1e0 lib/nlattr.c:117 [...] Call Trace: <TASK>
    __netlink_policy_dump_write_attr+0x23d/0x990 net/netlink/policy.c:310
    netlink_policy_dump_write_attr+0x22/0x30 net/netlink/policy.c:411 netlink_ack_tlv_fill
    net/netlink/af_netlink.c:2454 [inline] netlink_ack+0x546/0x760 net/netlink/af_netlink.c:2506
    netlink_rcv_skb+0x1b7/0x240 net/netlink/af_netlink.c:2546 rtnetlink_rcv+0x18/0x20
    net/core/rtnetlink.c:6109 netlink_unicast_kernel net/netlink/af_netlink.c:1319 [inline]
    netlink_unicast+0x5e9/0x6b0 net/netlink/af_netlink.c:1345 netlink_sendmsg+0x739/0x860
    net/netlink/af_netlink.c:1921 sock_sendmsg_nosec net/socket.c:714 [inline] sock_sendmsg net/socket.c:734
    [inline] ____sys_sendmsg+0x38f/0x500 net/socket.c:2482 ___sys_sendmsg net/socket.c:2536 [inline]
    __sys_sendmsg+0x197/0x230 net/socket.c:2565 __do_sys_sendmsg net/socket.c:2574 [inline] __se_sys_sendmsg
    net/socket.c:2572 [inline] __x64_sys_sendmsg+0x42/0x50 net/socket.c:2572 do_syscall_x64
    arch/x86/entry/common.c:50 [inline] do_syscall_64+0x2b/0x70 arch/x86/entry/common.c:80
    entry_SYSCALL_64_after_hwframe+0x63/0xcd (CVE-2023-52906)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52906");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/08/21");
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
       "match_one": {
        "os_version": [
         "8",
         "9"
        ]
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
