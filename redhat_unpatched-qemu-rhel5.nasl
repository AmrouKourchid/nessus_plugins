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
# extracted from Red Hat Security Advisory qemu. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(196234);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2016-1714",
    "CVE-2016-1981",
    "CVE-2016-2391",
    "CVE-2016-2841",
    "CVE-2016-2857",
    "CVE-2016-4001",
    "CVE-2016-4002",
    "CVE-2016-4453",
    "CVE-2016-4454",
    "CVE-2016-5403",
    "CVE-2016-7170",
    "CVE-2016-8669",
    "CVE-2016-8910",
    "CVE-2016-9921",
    "CVE-2016-9922",
    "CVE-2017-2615",
    "CVE-2017-2620",
    "CVE-2017-5525",
    "CVE-2017-5526",
    "CVE-2017-5579",
    "CVE-2017-6505",
    "CVE-2017-7718",
    "CVE-2017-7980",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-9330",
    "CVE-2017-11434",
    "CVE-2017-13672",
    "CVE-2017-13673",
    "CVE-2017-13711",
    "CVE-2017-15124",
    "CVE-2017-15289",
    "CVE-2018-5683",
    "CVE-2018-7858",
    "CVE-2018-11806",
    "CVE-2018-18849",
    "CVE-2019-9824",
    "CVE-2019-12068",
    "CVE-2019-12155",
    "CVE-2019-14378",
    "CVE-2019-15890",
    "CVE-2019-20808",
    "CVE-2020-1983",
    "CVE-2020-7039",
    "CVE-2020-8608",
    "CVE-2020-10756",
    "CVE-2020-11869",
    "CVE-2020-11947",
    "CVE-2020-13361",
    "CVE-2020-14364",
    "CVE-2020-14394",
    "CVE-2020-16092",
    "CVE-2020-25723",
    "CVE-2020-29129",
    "CVE-2020-29130",
    "CVE-2021-20196"
  );

  script_name(english:"RHEL 5 : qemu (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-2620");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:slirp4netns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:xen");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
