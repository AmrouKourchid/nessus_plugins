#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(230133);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-46999");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-46999");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: sctp: do asoc update earlier in
    sctp_sf_do_dupcook_a There's a panic that occurs in a few of envs, the call trace is as below: [] general
    protection fault, ... 0x29acd70f1000a: 0000 [#1] SMP PTI [] RIP:
    0010:sctp_ulpevent_notify_peer_addr_change+0x4b/0x1fa [sctp] [] sctp_assoc_control_transport+0x1b9/0x210
    [sctp] [] sctp_do_8_2_transport_strike.isra.16+0x15c/0x220 [sctp] []
    sctp_cmd_interpreter.isra.21+0x1231/0x1a10 [sctp] [] sctp_do_sm+0xc3/0x2a0 [sctp] []
    sctp_generate_timeout_event+0x81/0xf0 [sctp] This is caused by a transport use-after-free issue. When
    processing a duplicate COOKIE-ECHO chunk in sctp_sf_do_dupcook_a(), both COOKIE-ACK and SHUTDOWN chunks
    are allocated with the transort from the new asoc. However, later in the sideeffect machine, the old asoc
    is used to send them out and old asoc's shutdown_last_sent_to is set to the transport that SHUTDOWN chunk
    attached to in sctp_cmd_setup_t2(), which actually belongs to the new asoc. After the new_asoc is freed
    and the old asoc T2 timeout, the old asoc's shutdown_last_sent_to that is already freed would be accessed
    in sctp_sf_t2_timer_expire(). Thanks Alexander and Jere for helping dig into this issue. To fix it, this
    patch is to do the asoc update first, then allocate the COOKIE-ACK and SHUTDOWN chunks with the 'updated'
    old asoc. This would make more sense, as a chunk from an asoc shouldn't be sent out with another asoc. We
    had fixed quite a few issues caused by this. (CVE-2021-46999)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-46999");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/12");
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
