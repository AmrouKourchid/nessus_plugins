#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2013-1034-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-10341.
##

include('compat.inc');

if (description)
{
  script_id(181095);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2012-6544",
    "CVE-2012-6545",
    "CVE-2013-0914",
    "CVE-2013-1929",
    "CVE-2013-3222",
    "CVE-2013-3224",
    "CVE-2013-3231",
    "CVE-2013-3235"
  );

  script_name(english:"Oracle Linux 5 : ELSA-2013-1034-1: / kernel (ELSA-2013-10341) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-10341 advisory.

  - Heap-based buffer overflow in the tg3_read_vpd function in drivers/net/ethernet/broadcom/tg3.c in the
    Linux kernel before 3.8.6 allows physically proximate attackers to cause a denial of service (system
    crash) or possibly execute arbitrary code via crafted firmware that specifies a long string in the Vital
    Product Data (VPD) data structure. (CVE-2013-1929)

  - The Bluetooth protocol stack in the Linux kernel before 3.6 does not properly initialize certain
    structures, which allows local users to obtain sensitive information from kernel stack memory via a
    crafted application that targets the (1) L2CAP or (2) HCI implementation. (CVE-2012-6544)

  - The Bluetooth RFCOMM implementation in the Linux kernel before 3.6 does not properly initialize certain
    structures, which allows local users to obtain sensitive information from kernel memory via a crafted
    application. (CVE-2012-6545)

  - The flush_signal_handlers function in kernel/signal.c in the Linux kernel before 3.8.4 preserves the value
    of the sa_restorer field across an exec operation, which makes it easier for local users to bypass the
    ASLR protection mechanism via a crafted application containing a sigaction system call. (CVE-2013-0914)

  - The vcc_recvmsg function in net/atm/common.c in the Linux kernel before 3.9-rc7 does not initialize a
    certain length variable, which allows local users to obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system call. (CVE-2013-3222)

  - The bt_sock_recvmsg function in net/bluetooth/af_bluetooth.c in the Linux kernel before 3.9-rc7 does not
    properly initialize a certain length variable, which allows local users to obtain sensitive information
    from kernel stack memory via a crafted recvmsg or recvfrom system call. (CVE-2013-3224)

  - The llc_ui_recvmsg function in net/llc/af_llc.c in the Linux kernel before 3.9-rc7 does not initialize a
    certain length variable, which allows local users to obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system call. (CVE-2013-3231)

  - net/tipc/socket.c in the Linux kernel before 3.9-rc7 does not initialize a certain data structure and a
    certain length variable, which allows local users to obtain sensitive information from kernel stack memory
    via a crafted recvmsg or recvfrom system call. (CVE-2013-3235)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2013-1034-1.nasl (plugin ID 68843).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-1034-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-3235");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2013-1929");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/07/10");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.12.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.12.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.12.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.12.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.12.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.12.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.12.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.12.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2013-1034-1.nasl (plugin ID 68843) instead.");
