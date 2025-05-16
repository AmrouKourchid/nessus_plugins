#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(228592);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2024-35894");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2024-35894");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: mptcp: prevent BPF accessing lowat
    from a subflow socket. Alexei reported the following splat: WARNING: CPU: 32 PID: 3276 at
    net/mptcp/subflow.c:1430 subflow_data_ready+0x147/0x1c0 Modules linked in: dummy bpf_testmod(O) [last
    unloaded: bpf_test_no_cfi(O)] CPU: 32 PID: 3276 Comm: test_progs Tainted: GO 6.8.0-12873-g2c43c33bfd23
    Call Trace: <TASK> mptcp_set_rcvlowat+0x79/0x1d0 sk_setsockopt+0x6c0/0x1540 __bpf_setsockopt+0x6f/0x90
    bpf_sock_ops_setsockopt+0x3c/0x90 bpf_prog_509ce5db2c7f9981_bpf_test_sockopt_int+0xb4/0x11b
    bpf_prog_dce07e362d941d2b_bpf_test_socket_sockopt+0x12b/0x132
    bpf_prog_348c9b5faaf10092_skops_sockopt+0x954/0xe86 __cgroup_bpf_run_filter_sock_ops+0xbc/0x250
    tcp_connect+0x879/0x1160 tcp_v6_connect+0x50c/0x870 mptcp_connect+0x129/0x280
    __inet_stream_connect+0xce/0x370 inet_stream_connect+0x36/0x50 bpf_trampoline_6442491565+0x49/0xef
    inet_stream_connect+0x5/0x50 __sys_connect+0x63/0x90 __x64_sys_connect+0x14/0x20 The root cause of the
    issue is that bpf allows accessing mptcp-level proto_ops from a tcp subflow scope. Fix the issue detecting
    the problematic call and preventing any action. (CVE-2024-35894)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2024-35894");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/05/19");
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
    "name": "kernel-rt",
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
