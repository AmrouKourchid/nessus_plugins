#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# @DEPRECATED@
#
# Disabled on 2024-05-31.
# This plugin has been deprecated as it does not adhere to established standards for this style of check.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory squid. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195583);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-2569",
    "CVE-2016-2570",
    "CVE-2016-2571",
    "CVE-2016-2572",
    "CVE-2016-3948",
    "CVE-2016-10002",
    "CVE-2018-1172",
    "CVE-2018-19131",
    "CVE-2018-19132",
    "CVE-2018-1000024",
    "CVE-2018-1000027",
    "CVE-2019-12520",
    "CVE-2019-12521",
    "CVE-2019-12522",
    "CVE-2019-12523",
    "CVE-2019-12524",
    "CVE-2019-12525",
    "CVE-2019-12526",
    "CVE-2019-12528",
    "CVE-2019-12529",
    "CVE-2019-13345",
    "CVE-2019-18676",
    "CVE-2019-18677",
    "CVE-2019-18678",
    "CVE-2019-18679",
    "CVE-2019-18860",
    "CVE-2020-8449",
    "CVE-2020-8450",
    "CVE-2020-14058",
    "CVE-2020-15049",
    "CVE-2020-15810",
    "CVE-2020-15811",
    "CVE-2020-24606",
    "CVE-2020-25097",
    "CVE-2021-28116",
    "CVE-2021-28651",
    "CVE-2021-28652",
    "CVE-2021-31806",
    "CVE-2021-31807",
    "CVE-2021-31808",
    "CVE-2021-33620",
    "CVE-2021-46784",
    "CVE-2022-41318",
    "CVE-2023-46724",
    "CVE-2023-46728",
    "CVE-2023-49285",
    "CVE-2023-49286",
    "CVE-2023-49288",
    "CVE-2023-50269",
    "CVE-2024-23638",
    "CVE-2024-25617"
  );

  script_name(english:"RHEL 6 : squid (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-8450");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-12526");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:squid34");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
