#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2017-2930-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2017-29301.
##

include('compat.inc');

if (description)
{
  script_id(180756);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2016-8399",
    "CVE-2017-7184",
    "CVE-2017-7541",
    "CVE-2017-7542",
    "CVE-2017-7558",
    "CVE-2017-11176",
    "CVE-2017-14106",
    "CVE-2017-1000111",
    "CVE-2017-1000112"
  );

  script_name(english:"Oracle Linux 7 : ELSA-2017-2930-1: / kernel (ELSA-2017-29301) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 7 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2017-29301 advisory.

  - An elevation of privilege vulnerability in the kernel networking subsystem could enable a local malicious
    application to execute arbitrary code within the context of the kernel. This issue is rated as Moderate
    because it first requires compromising a privileged process and current compiler optimizations restrict
    access to the vulnerable code. Product: Android. Versions: Kernel-3.10, Kernel-3.18. Android ID:
    A-31349935. (CVE-2016-8399)

  - The xfrm_replay_verify_len function in net/xfrm/xfrm_user.c in the Linux kernel through 4.10.6 does not
    validate certain size data after an XFRM_MSG_NEWAE update, which allows local users to obtain root
    privileges or cause a denial of service (heap-based out-of-bounds access) by leveraging the CAP_NET_ADMIN
    capability, as demonstrated during a Pwn2Own competition at CanSecWest 2017 for the Ubuntu 16.10 linux-
    image-* package 4.8.0.41.52. (CVE-2017-7184)

  - The brcmf_cfg80211_mgmt_tx function in drivers/net/wireless/broadcom/brcm80211/brcmfmac/cfg80211.c in the
    Linux kernel before 4.12.3 allows local users to cause a denial of service (buffer overflow and system
    crash) or possibly gain privileges via a crafted NL80211_CMD_FRAME Netlink packet. (CVE-2017-7541)

  - Linux kernel: heap out-of-bounds in AF_PACKET sockets. This new issue is analogous to previously disclosed
    CVE-2016-8655. In both cases, a socket option that changes socket state may race with safety checks in
    packet_set_ring. Previously with PACKET_VERSION. This time with PACKET_RESERVE. The solution is similar:
    lock the socket for the update. This issue may be exploitable, we did not investigate further. As this
    issue affects PF_PACKET sockets, it requires CAP_NET_RAW in the process namespace. But note that with user
    namespaces enabled, any process can create a namespace in which it has CAP_NET_RAW. (CVE-2017-1000111)

  - The tcp_disconnect function in net/ipv4/tcp.c in the Linux kernel before 4.12 allows local users to cause
    a denial of service (__tcp_select_window divide-by-zero error and system crash) by triggering a disconnect
    within a certain tcp_recvmsg code path. (CVE-2017-14106)

  - Linux kernel: Exploitable memory corruption due to UFO to non-UFO path switch. When building a UFO packet
    with MSG_MORE __ip_append_data() calls ip_ufo_append_data() to append. However in between two send()
    calls, the append path can be switched from UFO to non-UFO one, which leads to a memory corruption. In
    case UFO packet lengths exceeds MTU, copy = maxfraglen - skb->len becomes negative on the non-UFO path and
    the branch to allocate new skb is taken. This triggers fragmentation and computation of fraggap =
    skb_prev->len - maxfraglen. Fraggap can exceed MTU, causing copy = datalen - transhdrlen - fraggap to
    become negative. Subsequently skb_copy_and_csum_bits() writes out-of-bounds. A similar issue is present in
    IPv6 code. The bug was introduced in e89e9cf539a2 ([IPv4/IPv6]: UFO Scatter-gather approach) on Oct 18
    2005. (CVE-2017-1000112)

  - The mq_notify function in the Linux kernel through 4.11.9 does not set the sock pointer to NULL upon entry
    into the retry logic. During a user-space close of a Netlink socket, it allows attackers to cause a denial
    of service (use-after-free) or possibly have unspecified other impact. (CVE-2017-11176)

  - The ip6_find_1stfragopt function in net/ipv6/output_core.c in the Linux kernel through 4.12.3 allows local
    users to cause a denial of service (integer overflow and infinite loop) by leveraging the ability to open
    a raw socket. (CVE-2017-7542)

  - A kernel data leak due to an out-of-bound read was found in the Linux kernel in
    inet_diag_msg_sctp{,l}addr_fill() and sctp_get_sctp_info() functions present since version 4.7-rc1 through
    version 4.13. A data leak happens when these functions fill in sockaddr data structures used to export
    socket's diagnostic information. As a result, up to 100 bytes of the slab data could be leaked to a
    userspace. (CVE-2017-7558)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2017-2930-1.nasl (plugin ID 104088).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2017-2930-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2016-8399");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-7541");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel UDP Fragmentation Offset (UFO) Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-abi-whitelists");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-tools-libs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:python-perf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2017-2930-1.nasl (plugin ID 104088) instead.");
