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
# extracted from Red Hat Security Advisory exiv2. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196435);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2017-9239",
    "CVE-2017-9953",
    "CVE-2017-11336",
    "CVE-2017-11337",
    "CVE-2017-11338",
    "CVE-2017-11340",
    "CVE-2017-11553",
    "CVE-2017-11591",
    "CVE-2017-11592",
    "CVE-2017-11683",
    "CVE-2017-12955",
    "CVE-2017-12956",
    "CVE-2017-12957",
    "CVE-2017-14857",
    "CVE-2017-14858",
    "CVE-2017-14859",
    "CVE-2017-14860",
    "CVE-2017-14861",
    "CVE-2017-14862",
    "CVE-2017-14863",
    "CVE-2017-14864",
    "CVE-2017-14865",
    "CVE-2017-14866",
    "CVE-2017-17669",
    "CVE-2017-1000126",
    "CVE-2017-1000127",
    "CVE-2017-1000128",
    "CVE-2018-10958",
    "CVE-2018-10999",
    "CVE-2018-12264",
    "CVE-2018-12265",
    "CVE-2018-16336",
    "CVE-2018-17581",
    "CVE-2018-19107",
    "CVE-2018-19108",
    "CVE-2018-19535",
    "CVE-2018-20096",
    "CVE-2018-20098",
    "CVE-2019-13109",
    "CVE-2019-13110",
    "CVE-2019-13111",
    "CVE-2019-13112",
    "CVE-2019-13113",
    "CVE-2019-13114",
    "CVE-2019-13504",
    "CVE-2019-14368",
    "CVE-2019-14369",
    "CVE-2019-14370",
    "CVE-2019-14982",
    "CVE-2019-17402",
    "CVE-2020-18771",
    "CVE-2020-18898",
    "CVE-2020-18899",
    "CVE-2020-19716",
    "CVE-2021-3482",
    "CVE-2021-29457",
    "CVE-2021-29458",
    "CVE-2021-29463",
    "CVE-2021-29464",
    "CVE-2021-29470",
    "CVE-2021-29473",
    "CVE-2021-29623",
    "CVE-2021-31291",
    "CVE-2021-31292",
    "CVE-2021-32617",
    "CVE-2021-32815",
    "CVE-2021-34334",
    "CVE-2021-34335",
    "CVE-2021-37615",
    "CVE-2021-37616",
    "CVE-2021-37618",
    "CVE-2021-37619",
    "CVE-2021-37620",
    "CVE-2021-37621",
    "CVE-2021-37622",
    "CVE-2021-37623",
    "CVE-2022-3717",
    "CVE-2022-3718",
    "CVE-2022-3719",
    "CVE-2022-3755",
    "CVE-2022-3756",
    "CVE-2022-3757"
  );

  script_name(english:"RHEL 6 : exiv2 (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-29464");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-12265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/05/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-exiv2-023");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-exiv2-026");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
