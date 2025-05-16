#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2012-1445-1.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2012-14451.
##

include('compat.inc');

if (description)
{
  script_id(181043);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2012-2100");

  script_name(english:"Oracle Linux 5 : ELSA-2012-1445-1: / kernel (ELSA-2012-14451) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2012-14451 advisory.

  - The ext4_fill_flex_info function in fs/ext4/super.c in the Linux kernel before 3.2.2, on the x86 platform
    and unspecified other platforms, allows user-assisted remote attackers to trigger inconsistent filesystem-
    groups data and possibly cause a denial of service via a malformed ext4 filesystem containing a super
    block with a large FLEX_BG group size (aka s_log_groups_per_flex value). NOTE: this vulnerability exists
    because of an incomplete fix for CVE-2009-4307. (CVE-2012-2100)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2012-1445-1.nasl (plugin ID 68653).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2012-1445-1.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2012-2100");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/11/13");
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.20.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.20.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.20.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ocfs2-2.6.18-308.20.1.0.1.el5xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.20.1.0.1.el5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.20.1.0.1.el5PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.20.1.0.1.el5debug");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:oracleasm-2.6.18-308.20.1.0.1.el5xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2012-1445-1.nasl (plugin ID 68653) instead.");
