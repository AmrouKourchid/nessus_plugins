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
# extracted from Red Hat Security Advisory ruby. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195418);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2016-2337",
    "CVE-2016-2338",
    "CVE-2016-7798",
    "CVE-2017-10784",
    "CVE-2017-17405",
    "CVE-2017-17742",
    "CVE-2017-17790",
    "CVE-2018-6914",
    "CVE-2018-8777",
    "CVE-2018-8778",
    "CVE-2018-8780",
    "CVE-2018-16395",
    "CVE-2018-16396",
    "CVE-2019-15845",
    "CVE-2019-16201",
    "CVE-2019-16254",
    "CVE-2019-16255",
    "CVE-2020-25613",
    "CVE-2021-28965",
    "CVE-2021-31810",
    "CVE-2021-41817",
    "CVE-2021-41819",
    "CVE-2022-28739",
    "CVE-2023-28755",
    "CVE-2023-28756",
    "CVE-2024-27280",
    "CVE-2024-27281",
    "CVE-2024-27282"
  );

  script_name(english:"RHEL 6 : ruby (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-17405");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-16395");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ruby");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
