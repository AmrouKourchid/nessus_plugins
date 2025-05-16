#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(226507);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2023-52881");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2023-52881");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: do not accept ACK of bytes we
    never sent This patch is based on a detailed report and ideas from Yepeng Pan and Christian Rossow. ACK
    seq validation is currently following RFC 5961 5.2 guidelines: The ACK value is considered acceptable only
    if it is in the range of ((SND.UNA - MAX.SND.WND) <= SEG.ACK <= SND.NXT). All incoming segments whose ACK
    value doesn't satisfy the above condition MUST be discarded and an ACK sent back. It needs to be noted
    that RFC 793 on page 72 (fifth check) says: If the ACK is a duplicate (SEG.ACK < SND.UNA), it can be
    ignored. If the ACK acknowledges something not yet sent (SEG.ACK > SND.NXT) then send an ACK, drop the
    segment, and return. The ignored above implies that the processing of the incoming data segment
    continues, which means the ACK value is treated as acceptable. This mitigation makes the ACK check more
    stringent since any ACK < SND.UNA wouldn't be accepted, instead only ACKs that are in the range ((SND.UNA
    - MAX.SND.WND) <= SEG.ACK <= SND.NXT) get through. This can be refined for new (and possibly spoofed)
    flows, by not accepting ACK for bytes that were never sent. This greatly improves TCP security at a little
    cost. I added a Fixes: tag to make sure this patch will reach stable trees, even if the 'blamed' patch was
    adhering to the RFC. tp->bytes_acked was added in linux-4.2 Following packetdrill test (courtesy of Yepeng
    Pan) shows the issue at hand: 0 socket(..., SOCK_STREAM, IPPROTO_TCP) = 3 +0 setsockopt(3, SOL_SOCKET,
    SO_REUSEADDR, [1], 4) = 0 +0 bind(3, ..., ...) = 0 +0 listen(3, 1024) = 0 // ---------------- Handshake
    ------------------- // // when window scale is set to 14 the window size can be extended to // 65535 *
    (2^14) = 1073725440. Linux would accept an ACK packet // with ack number in (Server_ISN+1-1073725440.
    Server_ISN+1) // ,though this ack number acknowledges some data never // sent by the server. +0 < S 0:0(0)
    win 65535 <mss 1400,nop,wscale 14> +0 > S. 0:0(0) ack 1 <...> +0 < . 1:1(0) ack 1 win 65535 +0 accept(3,
    ..., ...) = 4 // For the established connection, we send an ACK packet, // the ack packet uses ack number
    1 - 1073725300 + 2^32, // where 2^32 is used to wrap around. // Note: we used 1073725300 instead of
    1073725440 to avoid possible // edge cases. // 1 - 1073725300 + 2^32 = 3221241997 // Oops, old kernels
    happily accept this packet. +0 < . 1:1001(1000) ack 3221241997 win 65535 // After the kernel fix the
    following will be replaced by a challenge ACK, // and prior malicious frame would be dropped. +0 > .
    1:1(0) ack 1001 (CVE-2023-52881)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2023-52881");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/01/19");
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

var vdf_res = vdf::check_and_report(vuln_data:vuln_data, severity:SECURITY_HOLE);
vdf::handle_check_and_report_errors(vdf_result: vdf_res);
