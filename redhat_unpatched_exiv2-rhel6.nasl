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
# extracted from Red Hat Security Advisory exiv2. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(199672);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2014-9449",
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
    "CVE-2018-20098"
  );

  script_name(english:"RHEL 6 : exiv2 (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2020/cve-2020-18899.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b055da93");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12265");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:exiv2");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
