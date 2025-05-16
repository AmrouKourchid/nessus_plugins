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
# extracted from Red Hat Security Advisory flash-plugin. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196884);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-7867",
    "CVE-2016-7868",
    "CVE-2016-7869",
    "CVE-2016-7870",
    "CVE-2016-7871",
    "CVE-2016-7872",
    "CVE-2016-7873",
    "CVE-2016-7874",
    "CVE-2016-7875",
    "CVE-2016-7876",
    "CVE-2016-7877",
    "CVE-2016-7878",
    "CVE-2016-7879",
    "CVE-2016-7880",
    "CVE-2016-7881",
    "CVE-2016-7890",
    "CVE-2016-7892",
    "CVE-2017-2925",
    "CVE-2017-2926",
    "CVE-2017-2927",
    "CVE-2017-2928",
    "CVE-2017-2930",
    "CVE-2017-2931",
    "CVE-2017-2932",
    "CVE-2017-2933",
    "CVE-2017-2934",
    "CVE-2017-2935",
    "CVE-2017-2936",
    "CVE-2017-2937",
    "CVE-2017-2938",
    "CVE-2017-2982",
    "CVE-2017-2984",
    "CVE-2017-2985",
    "CVE-2017-2986",
    "CVE-2017-2987",
    "CVE-2017-2988",
    "CVE-2017-2990",
    "CVE-2017-2991",
    "CVE-2017-2992",
    "CVE-2017-2994",
    "CVE-2017-2995",
    "CVE-2017-2996",
    "CVE-2017-2997",
    "CVE-2017-2998",
    "CVE-2017-2999",
    "CVE-2017-3000",
    "CVE-2017-3001",
    "CVE-2017-3002",
    "CVE-2017-3003"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/04/15");

  script_name(english:"RHEL 5 : flash-plugin (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-3003");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/12/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:flash-plugin");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
