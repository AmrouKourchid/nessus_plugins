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
# extracted from Red Hat Security Advisory mysql. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198654);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2012-4414",
    "CVE-2012-5627",
    "CVE-2015-3152",
    "CVE-2015-4819",
    "CVE-2016-0502",
    "CVE-2016-0505",
    "CVE-2016-0546",
    "CVE-2016-0596",
    "CVE-2016-0597",
    "CVE-2016-0598",
    "CVE-2016-0600",
    "CVE-2016-0606",
    "CVE-2016-0608",
    "CVE-2016-0609",
    "CVE-2016-0616",
    "CVE-2016-2047",
    "CVE-2016-5483",
    "CVE-2016-5616",
    "CVE-2016-5617",
    "CVE-2016-6663",
    "CVE-2016-6664",
    "CVE-2017-3265",
    "CVE-2017-3291",
    "CVE-2017-3302",
    "CVE-2017-3308",
    "CVE-2017-3309",
    "CVE-2017-3312",
    "CVE-2017-3453",
    "CVE-2017-3461",
    "CVE-2017-3462",
    "CVE-2017-3463",
    "CVE-2017-3464",
    "CVE-2017-3600",
    "CVE-2017-3636",
    "CVE-2017-3641",
    "CVE-2017-3648",
    "CVE-2017-3651",
    "CVE-2017-3652",
    "CVE-2017-3653",
    "CVE-2017-10268",
    "CVE-2017-10379",
    "CVE-2018-2562",
    "CVE-2018-2622",
    "CVE-2018-2640",
    "CVE-2018-2665",
    "CVE-2018-2668",
    "CVE-2018-2755",
    "CVE-2018-2761",
    "CVE-2018-2771",
    "CVE-2018-2773",
    "CVE-2018-2781",
    "CVE-2018-2813",
    "CVE-2018-2817",
    "CVE-2018-2818",
    "CVE-2018-2819",
    "CVE-2018-3058",
    "CVE-2018-3063",
    "CVE-2018-3066",
    "CVE-2018-3081",
    "CVE-2018-3123",
    "CVE-2018-3133",
    "CVE-2018-3174",
    "CVE-2018-3282",
    "CVE-2019-2455",
    "CVE-2019-2481",
    "CVE-2019-2627",
    "CVE-2019-2683",
    "CVE-2019-2730",
    "CVE-2019-2737",
    "CVE-2019-2738",
    "CVE-2019-2739",
    "CVE-2019-2740",
    "CVE-2019-2805",
    "CVE-2020-2574",
    "CVE-2020-2579",
    "CVE-2020-2780",
    "CVE-2020-14550"
  );

  script_name(english:"RHEL 6 : mysql (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2024/cve-2024-21207.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8522c9aa");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-2562");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-2755");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mariadb-galera");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mysql");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
