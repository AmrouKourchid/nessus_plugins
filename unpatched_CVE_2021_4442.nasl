#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
##

include('compat.inc');

if (description)
{
  script_id(224283);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/03/05");

  script_cve_id("CVE-2021-4442");

  script_name(english:"Linux Distros Unpatched Vulnerability : CVE-2021-4442");

  script_set_attribute(attribute:"synopsis", value:
"The Linux/Unix host has one or more packages installed with a vulnerability that the vendor indicates will not be
patched.");
  script_set_attribute(attribute:"description", value:
"The Linux/Unix host has one or more packages installed that are impacted by a vulnerability without a vendor supplied
patch available.

  - In the Linux kernel, the following vulnerability has been resolved: tcp: add sanity tests to TCP_QUEUE_SEQ
    Qingyu Li reported a syzkaller bug where the repro changes RCV SEQ _after_ restoring data in the receive
    queue. mprotect(0x4aa000, 12288, PROT_READ) = 0 mmap(0x1ffff000, 4096, PROT_NONE,
    MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x1ffff000 mmap(0x20000000, 16777216,
    PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x20000000 mmap(0x21000000,
    4096, PROT_NONE, MAP_PRIVATE|MAP_FIXED|MAP_ANONYMOUS, -1, 0) = 0x21000000 socket(AF_INET6, SOCK_STREAM,
    IPPROTO_IP) = 3 setsockopt(3, SOL_TCP, TCP_REPAIR, [1], 4) = 0 connect(3, {sa_family=AF_INET6,
    sin6_port=htons(0), sin6_flowinfo=htonl(0), inet_pton(AF_INET6, ::1, &sin6_addr), sin6_scope_id=0}, 28)
    = 0 setsockopt(3, SOL_TCP, TCP_REPAIR_QUEUE, [1], 4) = 0 sendmsg(3, {msg_name=NULL, msg_namelen=0,
    msg_iov=[{iov_base=0x0000000000000003\0\0, iov_len=20}], msg_iovlen=1, msg_controllen=0, msg_flags=0},
    0) = 20 setsockopt(3, SOL_TCP, TCP_REPAIR, [0], 4) = 0 setsockopt(3, SOL_TCP, TCP_QUEUE_SEQ, [128], 4) = 0
    recvfrom(3, NULL, 20, 0, NULL, NULL) = -1 ECONNRESET (Connection reset by peer) syslog shows: [
    111.205099] TCP recvmsg seq # bug 2: copied 80, seq 0, rcvnxt 80, fl 0 [ 111.207894] WARNING: CPU: 1 PID:
    356 at net/ipv4/tcp.c:2343 tcp_recvmsg_locked+0x90e/0x29a0 This should not be allowed. TCP_QUEUE_SEQ
    should only be used when queues are empty. This patch fixes this case, and the tx path as well.
    (CVE-2021-4442)

Note that Nessus relies on the presence of the package as reported by the vendor.");
  script_set_attribute(attribute:"solution", value:
"There is no known solution at this time.");
  script_set_attribute(attribute:"agent", value:"unix");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-4442");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2022/01/11");
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
