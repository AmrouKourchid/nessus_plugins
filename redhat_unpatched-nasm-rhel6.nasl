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
# extracted from Red Hat Security Advisory nasm. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(195779);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2017-11111",
    "CVE-2017-14228",
    "CVE-2017-17810",
    "CVE-2017-17811",
    "CVE-2017-17812",
    "CVE-2017-17813",
    "CVE-2017-17814",
    "CVE-2017-17815",
    "CVE-2017-17816",
    "CVE-2017-17817",
    "CVE-2017-17818",
    "CVE-2017-17819",
    "CVE-2017-17820",
    "CVE-2018-8881",
    "CVE-2018-8882",
    "CVE-2018-8883",
    "CVE-2018-10016",
    "CVE-2018-10254",
    "CVE-2018-10316",
    "CVE-2018-16382",
    "CVE-2018-19213",
    "CVE-2018-19214",
    "CVE-2018-19215",
    "CVE-2018-19755",
    "CVE-2018-20535",
    "CVE-2018-20538",
    "CVE-2018-1000667",
    "CVE-2019-6290",
    "CVE-2019-6291",
    "CVE-2019-8343",
    "CVE-2019-20334",
    "CVE-2019-20352",
    "CVE-2020-18780",
    "CVE-2020-18974",
    "CVE-2020-21528",
    "CVE-2020-21685",
    "CVE-2020-21686",
    "CVE-2020-21687",
    "CVE-2020-24241",
    "CVE-2020-24242",
    "CVE-2020-24978",
    "CVE-2021-33450",
    "CVE-2021-33452",
    "CVE-2022-29654",
    "CVE-2022-41420",
    "CVE-2022-44368",
    "CVE-2022-44369",
    "CVE-2022-44370",
    "CVE-2022-46456",
    "CVE-2022-46457",
    "CVE-2023-31722",
    "CVE-2023-38665",
    "CVE-2023-38667",
    "CVE-2023-38668"
  );

  script_name(english:"RHEL 6 : nasm (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-24978");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/07/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:nasm");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
