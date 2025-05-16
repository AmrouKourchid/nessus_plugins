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
# extracted from Red Hat Security Advisory glibc. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2009-5155",
    "CVE-2011-5320",
    "CVE-2012-4412",
    "CVE-2012-4424",
    "CVE-2013-4237",
    "CVE-2013-4458",
    "CVE-2013-4788",
    "CVE-2014-4043",
    "CVE-2014-6040",
    "CVE-2014-7817",
    "CVE-2014-8121",
    "CVE-2014-9402",
    "CVE-2014-9761",
    "CVE-2015-1781",
    "CVE-2015-8776",
    "CVE-2015-8777",
    "CVE-2015-8778",
    "CVE-2015-8779",
    "CVE-2015-8982",
    "CVE-2015-8983",
    "CVE-2015-8984",
    "CVE-2015-8985",
    "CVE-2016-1234",
    "CVE-2016-3075",
    "CVE-2016-3706",
    "CVE-2016-10228",
    "CVE-2017-8804",
    "CVE-2017-12132",
    "CVE-2017-15670",
    "CVE-2017-15671",
    "CVE-2017-16997",
    "CVE-2018-6485",
    "CVE-2018-11236",
    "CVE-2019-9169"
  );

  script_name(english:"RHEL 5 : glibc (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2019/cve-2019-1010022.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a5ca17f5");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-16997");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2019-9169");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-glibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:glibc");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
