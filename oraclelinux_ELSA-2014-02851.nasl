#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2014-0285-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2014-02851.
##

include('compat.inc');

if (description)
{
  script_id(181048);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2013-2929",
    "CVE-2013-4483",
    "CVE-2013-4554",
    "CVE-2013-6381",
    "CVE-2013-6383",
    "CVE-2013-6885",
    "CVE-2013-7263"
  );

  script_name(english:"Oracle Linux 5 : ELSA-2014-0285-1: / kernel (ELSA-2014-02851) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2014-02851 advisory.

  - Xen 3.0.3 through 4.1.x (possibly 4.1.6.1), 4.2.x (possibly 4.2.3), and 4.3.x (possibly 4.3.1) does not
    properly prevent access to hypercalls, which allows local guest users to gain privileges via a crafted
    application running in ring 1 or 2. (CVE-2013-4554)

  - The Linux kernel before 3.12.2 does not properly use the get_dumpable function, which allows local users
    to bypass intended ptrace restrictions or obtain sensitive information from IA64 scratch registers via a
    crafted application, related to kernel/ptrace.c and arch/ia64/include/asm/processor.h. (CVE-2013-2929)

  - Buffer overflow in the qeth_snmp_command function in drivers/s390/net/qeth_core_main.c in the Linux kernel
    through 3.12.1 allows local users to cause a denial of service or possibly have unspecified other impact
    via an SNMP ioctl call with a length value that is incompatible with the command-buffer size.
    (CVE-2013-6381)

  - The Linux kernel before 3.12.4 updates certain length values before ensuring that associated data
    structures have been initialized, which allows local users to obtain sensitive information from kernel
    stack memory via a (1) recvfrom, (2) recvmmsg, or (3) recvmsg system call, related to net/ipv4/ping.c,
    net/ipv4/raw.c, net/ipv4/udp.c, net/ipv6/raw.c, and net/ipv6/udp.c. (CVE-2013-7263)

  - The ipc_rcu_putref function in ipc/util.c in the Linux kernel before 3.10 does not properly manage a
    reference count, which allows local users to cause a denial of service (memory consumption or system
    crash) via a crafted application. (CVE-2013-4483)

  - The aac_compat_ioctl function in drivers/scsi/aacraid/linit.c in the Linux kernel before 3.11.8 does not
    require the CAP_SYS_RAWIO capability, which allows local users to bypass intended access restrictions via
    a crafted ioctl call. (CVE-2013-6383)

  - The microcode on AMD 16h 00h through 0Fh processors does not properly handle the interaction between
    locked instructions and write-combined memory types, which allows local users to cause a denial of service
    (system hang) via a crafted application, aka the errata 793 issue. (CVE-2013-6885)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2014-0285-1.nasl (plugin ID 73006).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2014-0285-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-6383");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-4483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/13");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.6.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.6.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.6.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-371.6.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.6.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.6.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.6.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-371.6.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2014-0285-1.nasl (plugin ID 73006) instead.");
