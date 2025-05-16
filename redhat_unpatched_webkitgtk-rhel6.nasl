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
# extracted from Red Hat Security Advisory webkitgtk. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199473);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2010-1761",
    "CVE-2010-1806",
    "CVE-2010-1813",
    "CVE-2010-2901",
    "CVE-2010-3408",
    "CVE-2010-3409",
    "CVE-2010-3410",
    "CVE-2010-4037",
    "CVE-2010-4040",
    "CVE-2010-4042",
    "CVE-2010-4199",
    "CVE-2010-4201",
    "CVE-2010-4205",
    "CVE-2010-4492",
    "CVE-2010-4493",
    "CVE-2010-4578",
    "CVE-2011-0482",
    "CVE-2011-0778",
    "CVE-2011-3064",
    "CVE-2013-2871",
    "CVE-2013-2875",
    "CVE-2013-2927",
    "CVE-2014-1292",
    "CVE-2014-1297",
    "CVE-2014-1298",
    "CVE-2014-1299",
    "CVE-2014-1300",
    "CVE-2014-1303",
    "CVE-2014-1304",
    "CVE-2014-1305",
    "CVE-2014-1307",
    "CVE-2014-1308",
    "CVE-2014-1309",
    "CVE-2014-1311",
    "CVE-2014-1313",
    "CVE-2014-1323",
    "CVE-2014-1326",
    "CVE-2014-1329",
    "CVE-2014-1330",
    "CVE-2014-1331",
    "CVE-2014-1333",
    "CVE-2014-1334",
    "CVE-2014-1335",
    "CVE-2014-1336",
    "CVE-2014-1337",
    "CVE-2014-1338",
    "CVE-2014-1339",
    "CVE-2014-1341",
    "CVE-2014-1342",
    "CVE-2014-1343",
    "CVE-2014-1344",
    "CVE-2014-1346",
    "CVE-2014-1384",
    "CVE-2014-1385",
    "CVE-2014-1386",
    "CVE-2014-1387",
    "CVE-2014-1388",
    "CVE-2014-1389",
    "CVE-2014-1390",
    "CVE-2014-1713",
    "CVE-2014-1731",
    "CVE-2014-3192",
    "CVE-2014-3200",
    "CVE-2014-7907",
    "CVE-2014-7908",
    "CVE-2014-7910",
    "CVE-2015-1209",
    "CVE-2015-1212",
    "CVE-2017-7156",
    "CVE-2017-7157",
    "CVE-2017-13856",
    "CVE-2017-13866",
    "CVE-2017-13870",
    "CVE-2018-4121",
    "CVE-2018-4200",
    "CVE-2018-4204",
    "CVE-2018-11712",
    "CVE-2018-11713",
    "CVE-2019-6237",
    "CVE-2019-8571",
    "CVE-2019-8583",
    "CVE-2019-8584",
    "CVE-2019-8586",
    "CVE-2019-8587",
    "CVE-2019-8594",
    "CVE-2019-8595",
    "CVE-2019-8596",
    "CVE-2019-8597",
    "CVE-2019-8601",
    "CVE-2019-8607",
    "CVE-2019-8608",
    "CVE-2019-8609",
    "CVE-2019-8610",
    "CVE-2019-8611",
    "CVE-2019-8615",
    "CVE-2019-8619",
    "CVE-2019-8622",
    "CVE-2019-8623",
    "CVE-2019-8625",
    "CVE-2019-8644",
    "CVE-2019-8649",
    "CVE-2019-8658",
    "CVE-2019-8666",
    "CVE-2019-8669",
    "CVE-2019-8671",
    "CVE-2019-8672",
    "CVE-2019-8673",
    "CVE-2019-8674",
    "CVE-2019-8676",
    "CVE-2019-8677",
    "CVE-2019-8678",
    "CVE-2019-8679",
    "CVE-2019-8680",
    "CVE-2019-8681",
    "CVE-2019-8683",
    "CVE-2019-8684",
    "CVE-2019-8686",
    "CVE-2019-8687",
    "CVE-2019-8688",
    "CVE-2019-8689",
    "CVE-2019-8690",
    "CVE-2019-8707",
    "CVE-2019-8710",
    "CVE-2019-8719",
    "CVE-2019-8720",
    "CVE-2019-8726",
    "CVE-2019-8733",
    "CVE-2019-8735",
    "CVE-2019-8743",
    "CVE-2019-8763",
    "CVE-2019-8764",
    "CVE-2019-8765",
    "CVE-2019-8766",
    "CVE-2019-8768",
    "CVE-2019-8769",
    "CVE-2019-8771",
    "CVE-2019-8782",
    "CVE-2019-8783",
    "CVE-2019-8808",
    "CVE-2019-8811",
    "CVE-2019-8812",
    "CVE-2019-8813",
    "CVE-2019-8814",
    "CVE-2019-8815",
    "CVE-2019-8816",
    "CVE-2019-8819",
    "CVE-2019-8820",
    "CVE-2019-8821",
    "CVE-2019-8822",
    "CVE-2019-8823",
    "CVE-2020-3862",
    "CVE-2020-3864",
    "CVE-2020-3865",
    "CVE-2020-3867",
    "CVE-2020-3868",
    "CVE-2020-3885",
    "CVE-2020-3894",
    "CVE-2020-3895",
    "CVE-2020-3897",
    "CVE-2020-3899",
    "CVE-2020-3900",
    "CVE-2020-3901",
    "CVE-2020-3902",
    "CVE-2021-30762",
    "CVE-2022-42856",
    "CVE-2023-23529"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2021/11/17");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/13");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/01/04");
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2023/03/07");

  script_name(english:"RHEL 6 : webkitgtk (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2014/cve-2014-1745.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c0013e1f");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2014-1303");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2010-4205");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:webkitgtk");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
