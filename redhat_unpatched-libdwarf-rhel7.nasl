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
# extracted from Red Hat Security Advisory libdwarf. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196160);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-2091",
    "CVE-2016-5027",
    "CVE-2016-5028",
    "CVE-2016-5029",
    "CVE-2016-5030",
    "CVE-2016-5031",
    "CVE-2016-5032",
    "CVE-2016-5033",
    "CVE-2016-5034",
    "CVE-2016-5035",
    "CVE-2016-5036",
    "CVE-2016-5037",
    "CVE-2016-5038",
    "CVE-2016-5039",
    "CVE-2016-5040",
    "CVE-2016-5041",
    "CVE-2016-5042",
    "CVE-2016-5043",
    "CVE-2016-5044",
    "CVE-2016-7410",
    "CVE-2016-7510",
    "CVE-2016-7511",
    "CVE-2016-8679",
    "CVE-2016-8680",
    "CVE-2016-8681",
    "CVE-2016-9276",
    "CVE-2016-9480",
    "CVE-2016-9558",
    "CVE-2017-9052",
    "CVE-2017-9053",
    "CVE-2017-9054",
    "CVE-2017-9055",
    "CVE-2017-9998",
    "CVE-2019-14249",
    "CVE-2020-27545",
    "CVE-2020-28163",
    "CVE-2024-2002",
    "CVE-2024-31745"
  );

  script_name(english:"RHEL 7 : libdwarf (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9055");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libdwarf");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
