#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2012-1540-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-15401.
##

include('compat.inc');

if (description)
{
  script_id(181116);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id(
    "CVE-2012-2372",
    "CVE-2012-3552",
    "CVE-2012-4508",
    "CVE-2012-4535",
    "CVE-2012-4537",
    "CVE-2012-5513"
  );

  script_name(english:"Oracle Linux 5 : ELSA-2012-1540-1: / kernel (ELSA-2012-15401) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by multiple vulnerabilities as referenced in the
ELSA-2012-15401 advisory.

  - The rds_ib_xmit function in net/rds/ib_send.c in the Reliable Datagram Sockets (RDS) protocol
    implementation in the Linux kernel 3.7.4 and earlier allows local users to cause a denial of service
    (BUG_ON and kernel panic) by establishing an RDS connection with the source IP address equal to the IPoIB
    interface's own IP address, as demonstrated by rds-ping. (CVE-2012-2372)

  - Race condition in the IP implementation in the Linux kernel before 3.0 might allow remote attackers to
    cause a denial of service (slab corruption and system crash) by sending packets to an application that
    sets socket options during the handling of network traffic. (CVE-2012-3552)

  - Race condition in fs/ext4/extents.c in the Linux kernel before 3.4.16 allows local users to obtain
    sensitive information from a deleted file by reading an extent that was not properly marked as
    uninitialized. (CVE-2012-4508)

  - Xen 3.4 through 4.2, and possibly earlier versions, allows local guest OS administrators to cause a denial
    of service (Xen infinite loop and physical CPU consumption) by setting a VCPU with an inappropriate
    deadline. (CVE-2012-4535)

  - Xen 3.4 through 4.2, and possibly earlier versions, does not properly synchronize the p2m and m2p tables
    when the set_p2m_entry function fails, which allows local HVM guest OS administrators to cause a denial of
    service (memory consumption and assertion failure), aka Memory mapping failure DoS vulnerability.
    (CVE-2012-4537)

  - The XENMEM_exchange handler in Xen 4.2 and earlier does not properly check the memory address, which
    allows local PV guest OS administrators to cause a denial of service (crash) or possibly gain privileges
    via unspecified vectors that overwrite memory in the hypervisor reserved range. (CVE-2012-5513)

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2012-1540-1.nasl (plugin ID 68662).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-1540-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-5513");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2012-3552");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/06/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/05");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.24.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.24.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.24.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.24.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.24.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.24.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.24.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.24.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2012-1540-1.nasl (plugin ID 68662) instead.");
