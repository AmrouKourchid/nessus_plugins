#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2025-02-12.
# Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory rdesktop. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199010);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2018-8791",
    "CVE-2018-8792",
    "CVE-2018-8793",
    "CVE-2018-8794",
    "CVE-2018-8795",
    "CVE-2018-8796",
    "CVE-2018-8797",
    "CVE-2018-8798",
    "CVE-2018-8799",
    "CVE-2018-8800",
    "CVE-2018-20174",
    "CVE-2018-20175",
    "CVE-2018-20176",
    "CVE-2018-20177",
    "CVE-2018-20178",
    "CVE-2018-20179",
    "CVE-2018-20180",
    "CVE-2018-20181",
    "CVE-2018-20182"
  );

  script_name(english:"RHEL 6 : rdesktop (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-8800");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rdesktop");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
