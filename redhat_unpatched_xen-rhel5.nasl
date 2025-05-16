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
# extracted from Red Hat Security Advisory xen. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199537);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2014-3672",
    "CVE-2015-3209",
    "CVE-2015-5165",
    "CVE-2015-5307",
    "CVE-2015-6815",
    "CVE-2015-6855",
    "CVE-2015-7504",
    "CVE-2015-7512",
    "CVE-2015-7971",
    "CVE-2015-8104",
    "CVE-2015-8338",
    "CVE-2015-8339",
    "CVE-2015-8340",
    "CVE-2015-8554",
    "CVE-2015-8555",
    "CVE-2015-8743",
    "CVE-2016-1571",
    "CVE-2016-1981",
    "CVE-2016-2270",
    "CVE-2016-2271",
    "CVE-2016-2391",
    "CVE-2016-2841",
    "CVE-2016-3712",
    "CVE-2016-3960",
    "CVE-2016-3961",
    "CVE-2016-4962",
    "CVE-2016-4963",
    "CVE-2016-5403",
    "CVE-2016-6258",
    "CVE-2016-6259",
    "CVE-2016-7092",
    "CVE-2016-7093",
    "CVE-2016-7094",
    "CVE-2016-7777",
    "CVE-2016-8669",
    "CVE-2016-8910",
    "CVE-2016-9379",
    "CVE-2016-9380",
    "CVE-2016-9383",
    "CVE-2016-9386",
    "CVE-2016-9815",
    "CVE-2016-9816",
    "CVE-2016-9817",
    "CVE-2016-9818",
    "CVE-2016-9921",
    "CVE-2016-9922",
    "CVE-2016-9932",
    "CVE-2016-10013",
    "CVE-2016-10024",
    "CVE-2017-2615",
    "CVE-2017-2620",
    "CVE-2017-5526",
    "CVE-2017-5579",
    "CVE-2017-6505",
    "CVE-2017-7228",
    "CVE-2017-7718",
    "CVE-2017-7980",
    "CVE-2017-7995",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-8903",
    "CVE-2017-8904",
    "CVE-2017-8905",
    "CVE-2017-9330",
    "CVE-2017-10912",
    "CVE-2017-10913",
    "CVE-2017-10914",
    "CVE-2017-10915",
    "CVE-2017-10918",
    "CVE-2017-10919",
    "CVE-2017-10920",
    "CVE-2017-10921",
    "CVE-2017-10922",
    "CVE-2017-12134",
    "CVE-2017-12135",
    "CVE-2017-12137",
    "CVE-2017-12855",
    "CVE-2017-13672",
    "CVE-2017-13673",
    "CVE-2017-14316",
    "CVE-2017-14317",
    "CVE-2017-14318",
    "CVE-2017-14319",
    "CVE-2017-14431",
    "CVE-2017-15124",
    "CVE-2017-15289",
    "CVE-2017-15588",
    "CVE-2017-15589",
    "CVE-2017-15590",
    "CVE-2017-15591",
    "CVE-2017-15592",
    "CVE-2017-15594",
    "CVE-2017-15595",
    "CVE-2017-15597",
    "CVE-2017-17564",
    "CVE-2017-17566",
    "CVE-2018-5683",
    "CVE-2018-7540",
    "CVE-2018-7858",
    "CVE-2018-12891",
    "CVE-2018-18849",
    "CVE-2018-19963",
    "CVE-2018-19964",
    "CVE-2018-19966",
    "CVE-2019-17341",
    "CVE-2019-17342",
    "CVE-2019-17343",
    "CVE-2019-17344",
    "CVE-2019-17346",
    "CVE-2019-17348"
  );

  script_name(english:"RHEL 5 : xen (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-10921");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
