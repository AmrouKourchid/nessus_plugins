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
# extracted from Red Hat Security Advisory ghostscript. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196514);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-10217",
    "CVE-2016-10218",
    "CVE-2016-10219",
    "CVE-2016-10220",
    "CVE-2016-10317",
    "CVE-2017-5951",
    "CVE-2017-7207",
    "CVE-2017-8908",
    "CVE-2017-9610",
    "CVE-2017-9611",
    "CVE-2017-9612",
    "CVE-2017-9618",
    "CVE-2017-9619",
    "CVE-2017-9620",
    "CVE-2017-9726",
    "CVE-2017-9727",
    "CVE-2017-9739",
    "CVE-2017-9740",
    "CVE-2017-9835",
    "CVE-2017-11714",
    "CVE-2018-10194",
    "CVE-2018-11645",
    "CVE-2018-15908",
    "CVE-2018-15909",
    "CVE-2018-15910",
    "CVE-2018-15911",
    "CVE-2018-16511",
    "CVE-2018-16539",
    "CVE-2018-16540",
    "CVE-2018-16541",
    "CVE-2018-16542",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477",
    "CVE-2018-19478",
    "CVE-2019-3835",
    "CVE-2019-3838",
    "CVE-2019-3839",
    "CVE-2019-6116",
    "CVE-2019-10216",
    "CVE-2019-14811",
    "CVE-2019-14812",
    "CVE-2019-14813",
    "CVE-2019-14817",
    "CVE-2020-14373",
    "CVE-2020-16287",
    "CVE-2020-16288",
    "CVE-2020-16289",
    "CVE-2020-16290",
    "CVE-2020-16291",
    "CVE-2020-16292",
    "CVE-2020-16293",
    "CVE-2020-16294",
    "CVE-2020-16295",
    "CVE-2020-16296",
    "CVE-2020-16297",
    "CVE-2020-16298",
    "CVE-2020-16299",
    "CVE-2020-16300",
    "CVE-2020-16301",
    "CVE-2020-16302",
    "CVE-2020-16303",
    "CVE-2020-16304",
    "CVE-2020-16305",
    "CVE-2020-16306",
    "CVE-2020-16307",
    "CVE-2020-16308",
    "CVE-2020-16309",
    "CVE-2020-16310",
    "CVE-2020-17538",
    "CVE-2020-21710",
    "CVE-2020-21890",
    "CVE-2020-27792",
    "CVE-2021-45944",
    "CVE-2023-28879",
    "CVE-2023-36664",
    "CVE-2023-38559",
    "CVE-2023-38560",
    "CVE-2023-43115",
    "CVE-2023-46751"
  );

  script_name(english:"RHEL 6 : ghostscript (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-14813");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-28879");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
