#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2023/10/05. Deprecated by oraclelinux_ELSA-2007-0559-2.nasl.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisory ELSA-2007-0559.
##

include('compat.inc');

if (description)
{
  script_id(180616);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2023/10/06");

  script_cve_id("CVE-2007-3374");

  script_name(english:"Oracle Linux 5 : Important: / cman (ELSA-2007-0559) (deprecated)");

  script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
  script_set_attribute(attribute:"description", value:
"The remote Oracle Linux 5 host has packages installed that are affected by a vulnerability as referenced in the
ELSA-2007-0559 advisory.

  - Buffer overflow in cluster/cman/daemon/daemon.c in cman (redhat-cluster-suite) before 20070622 allows
    local users to cause a denial of service (crash) and possibly execute arbitrary code via long client
    messages. (CVE-2007-3374)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.

This plugin has been deprecated as it is a duplicate of oraclelinux_ELSA-2007-0559-2.nasl (plugin ID 67534).");
  script_set_attribute(attribute:"see_also", value:"https://linux.oracle.com/errata/ELSA-2007-0559.html");
  script_set_attribute(attribute:"solution", value:
"n/a");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2007-3374");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/06/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2023/09/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cman");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:cman-devel");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Oracle Linux Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2023 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_require_keys("Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/local_checks_enabled");

  exit(0);
}

exit(0, "This plugin has been deprecated. Use oraclelinux_ELSA-2007-0559-2.nasl (plugin ID 67534) instead.");
