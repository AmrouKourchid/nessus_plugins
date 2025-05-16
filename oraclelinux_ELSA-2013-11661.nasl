#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2013-1166-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-11661.
##

include('compat.inc');

if (description)
{
  script_id(181055);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2013-2147",
    "CVE-2013-2164",
    "CVE-2013-2206",
    "CVE-2013-2224",
    "CVE-2013-2232",
    "CVE-2013-2234",
    "CVE-2013-2237"
  );

  script_name(english:"Oracle Linux 5 : ELSA-2013-1166-1: / kernel (ELSA-2013-11661) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-11661 advisory.

  - The HP Smart Array controller disk-array driver and Compaq SMART2 controller disk-array driver in the
    Linux kernel through 3.9.4 do not initialize certain data structures, which allows local users to obtain
    sensitive information from kernel memory via (1) a crafted IDAGETPCIINFO command for a /dev/ida device,
    related to the ida_locked_ioctl function in drivers/block/cpqarray.c or (2) a crafted CCISS_PASSTHRU32
    command for a /dev/cciss device, related to the cciss_ioctl32_passthru function in drivers/block/cciss.c.
    (CVE-2013-2147)

  - The mmc_ioctl_cdrom_read_data function in drivers/cdrom/cdrom.c in the Linux kernel through 3.10 allows
    local users to obtain sensitive information from kernel memory via a read operation on a malfunctioning
    CD-ROM drive. (CVE-2013-2164)

  - The sctp_sf_do_5_2_4_dupcook function in net/sctp/sm_statefuns.c in the SCTP implementation in the Linux
    kernel before 3.8.5 does not properly handle associations during the processing of a duplicate COOKIE ECHO
    chunk, which allows remote attackers to cause a denial of service (NULL pointer dereference and system
    crash) or possibly have unspecified other impact via crafted SCTP traffic. (CVE-2013-2206)

  - A certain Red Hat patch for the Linux kernel 2.6.32 on Red Hat Enterprise Linux (RHEL) 6 allows local
    users to cause a denial of service (invalid free operation and system crash) or possibly gain privileges
    via a sendmsg system call with the IP_RETOPTS option, as demonstrated by hemlock.c. NOTE: this
    vulnerability exists because of an incorrect fix for CVE-2012-3552. (CVE-2013-2224)

  - The ip6_sk_dst_check function in net/ipv6/ip6_output.c in the Linux kernel before 3.10 allows local users
    to cause a denial of service (system crash) by using an AF_INET6 socket for a connection to an IPv4
    interface. (CVE-2013-2232)

  - The (1) key_notify_sa_flush and (2) key_notify_policy_flush functions in net/key/af_key.c in the Linux
    kernel before 3.10 do not initialize certain structure members, which allows local users to obtain
    sensitive information from kernel heap memory by reading a broadcast message from the notify interface of
    an IPSec key_socket. (CVE-2013-2234)

  - The key_notify_policy_flush function in net/key/af_key.c in the Linux kernel before 3.9 does not
    initialize a certain structure member, which allows local users to obtain sensitive information from
    kernel heap memory by reading a broadcast message from the notify_policy interface of an IPSec key_socket.
    (CVE-2013-2237)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2013-1166-1.nasl (plugin ID 69455).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1166-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-2224");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-2237");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/08/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-debug-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:kernel-xen-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.16.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.16.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.16.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.16.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.16.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.16.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.16.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.16.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2013-1166-1.nasl (plugin ID 69455) instead.");
