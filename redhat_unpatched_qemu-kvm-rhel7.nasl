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
# extracted from Red Hat Security Advisory qemu-kvm. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198727);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2015-5745",
    "CVE-2015-7549",
    "CVE-2015-8504",
    "CVE-2015-8558",
    "CVE-2015-8567",
    "CVE-2015-8568",
    "CVE-2015-8613",
    "CVE-2016-1922",
    "CVE-2016-2198",
    "CVE-2016-2392",
    "CVE-2016-2538",
    "CVE-2016-2858",
    "CVE-2016-4037",
    "CVE-2016-6834",
    "CVE-2016-6888",
    "CVE-2016-7116",
    "CVE-2016-7421",
    "CVE-2016-7423",
    "CVE-2016-7907",
    "CVE-2016-7908",
    "CVE-2016-7909",
    "CVE-2016-8576",
    "CVE-2016-8909",
    "CVE-2016-9102",
    "CVE-2016-9103",
    "CVE-2016-9104",
    "CVE-2016-9105",
    "CVE-2016-9106",
    "CVE-2016-9907",
    "CVE-2016-9911",
    "CVE-2016-9923",
    "CVE-2016-10155",
    "CVE-2017-5973",
    "CVE-2017-6414",
    "CVE-2017-9373",
    "CVE-2017-9374",
    "CVE-2017-9375",
    "CVE-2017-10806",
    "CVE-2017-18043",
    "CVE-2018-10839",
    "CVE-2018-12617",
    "CVE-2018-17958",
    "CVE-2018-17963",
    "CVE-2019-8934",
    "CVE-2020-13765",
    "CVE-2020-25743",
    "CVE-2020-27617"
  );

  script_name(english:"RHEL 7 : qemu-kvm (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17963");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virtio-win");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
