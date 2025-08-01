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
# extracted from Red Hat Security Advisory bluez. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196471);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2024/05/31");

  script_cve_id(
    "CVE-2016-7837",
    "CVE-2016-9797",
    "CVE-2016-9798",
    "CVE-2016-9800",
    "CVE-2016-9801",
    "CVE-2016-9803",
    "CVE-2016-9804",
    "CVE-2019-8921",
    "CVE-2019-8922",
    "CVE-2020-27153",
    "CVE-2021-3588",
    "CVE-2021-3658",
    "CVE-2021-41229",
    "CVE-2022-3563",
    "CVE-2022-3637",
    "CVE-2022-39176",
    "CVE-2022-39177",
    "CVE-2023-27349",
    "CVE-2023-45866"
  );

  script_name(english:"RHEL 6 : bluez (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27153");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2022-39177");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-hcidump");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:bluez-utils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
