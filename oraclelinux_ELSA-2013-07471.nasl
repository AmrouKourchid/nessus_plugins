#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2013-0747-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2013-07471.
##

include('compat.inc');

if (description)
{
  script_id(181115);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2012-6537",
    "CVE-2012-6542",
    "CVE-2012-6546",
    "CVE-2012-6547",
    "CVE-2013-0216",
    "CVE-2013-0231",
    "CVE-2013-1826"
  );

  script_name(english:"Oracle Linux 5 : ELSA-2013-0747-1: / kernel (ELSA-2013-07471) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2013-07471 advisory.

  - The pciback_enable_msi function in the PCI backend driver
    (drivers/xen/pciback/conf_space_capability_msi.c) in Xen for the Linux kernel 2.6.18 and 3.8 allows guest
    OS users with PCI device access to cause a denial of service via a large number of kernel log messages.
    NOTE: some of these details are obtained from third party information. (CVE-2013-0231)

  - The Xen netback functionality in the Linux kernel before 3.7.8 allows guest OS users to cause a denial of
    service (loop) by triggering ring pointer corruption. (CVE-2013-0216)

  - net/xfrm/xfrm_user.c in the Linux kernel before 3.6 does not initialize certain structures, which allows
    local users to obtain sensitive information from kernel memory by leveraging the CAP_NET_ADMIN capability.
    (CVE-2012-6537)

  - The llc_ui_getname function in net/llc/af_llc.c in the Linux kernel before 3.6 has an incorrect return
    value in certain circumstances, which allows local users to obtain sensitive information from kernel stack
    memory via a crafted application that leverages an uninitialized pointer argument. (CVE-2012-6542)

  - The ATM implementation in the Linux kernel before 3.6 does not initialize certain structures, which allows
    local users to obtain sensitive information from kernel stack memory via a crafted application.
    (CVE-2012-6546)

  - The __tun_chr_ioctl function in drivers/net/tun.c in the Linux kernel before 3.6 does not initialize a
    certain structure, which allows local users to obtain sensitive information from kernel stack memory via a
    crafted application. (CVE-2012-6547)

  - The xfrm_state_netlink function in net/xfrm/xfrm_user.c in the Linux kernel before 3.5.7 does not properly
    handle error conditions in dump_one_state function calls, which allows local users to gain privileges or
    cause a denial of service (NULL pointer dereference and system crash) by leveraging the CAP_NET_ADMIN
    capability. (CVE-2013-1826)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2013-0747-1.nasl (plugin ID 68808).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2013-0747-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2013-1826");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/16");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.4.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.4.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.4.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-348.4.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.4.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.4.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.4.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-348.4.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2013-0747-1.nasl (plugin ID 68808) instead.");
