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
# extracted from Red Hat Security Advisory exiv2. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199648);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2019-17402",
    "CVE-2020-18771",
    "CVE-2021-29470",
    "CVE-2021-29473",
    "CVE-2021-29623",
    "CVE-2021-32617",
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-34335",
    "CVE-2021-37615",
    "CVE-2021-37616",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622",
    "CVE-2021-37623"
  );

  script_name(english:"RHEL 8 : exiv2 (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-18899.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b055da93");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-18771");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-exiv2-026");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
