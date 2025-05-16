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
  script_id(196203);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/04/28");

  script_cve_id(
    "CVE-2016-1922",
    "CVE-2016-1981",
    "CVE-2016-2197",
    "CVE-2016-2198",
    "CVE-2016-2391",
    "CVE-2016-2392",
    "CVE-2016-2538",
    "CVE-2016-2841",
    "CVE-2016-2858",
    "CVE-2016-4001",
    "CVE-2016-4002",
    "CVE-2016-4037",
    "CVE-2016-4453",
    "CVE-2016-4454",
    "CVE-2016-4964",
    "CVE-2016-6834",
    "CVE-2016-6888",
    "CVE-2016-7116",
    "CVE-2016-7421",
    "CVE-2016-7423",
    "CVE-2016-7466",
    "CVE-2016-7907",
    "CVE-2016-7908",
    "CVE-2016-7909",
    "CVE-2016-7994",
    "CVE-2016-8576",
    "CVE-2016-8577",
    "CVE-2016-8669",
    "CVE-2016-8909",
    "CVE-2016-8910",
    "CVE-2016-9102",
    "CVE-2016-9103",
    "CVE-2016-9104",
    "CVE-2016-9105",
    "CVE-2016-9106",
    "CVE-2016-9907",
    "CVE-2016-9911",
    "CVE-2016-9921",
    "CVE-2016-9922",
    "CVE-2016-9923",
    "CVE-2016-10155",
    "CVE-2017-5579",
    "CVE-2017-5898",
    "CVE-2017-5973",
    "CVE-2017-6414",
    "CVE-2017-8309",
    "CVE-2017-8379",
    "CVE-2017-9373",
    "CVE-2017-9374",
    "CVE-2017-9375",
    "CVE-2017-10806",
    "CVE-2017-11434",
    "CVE-2017-12809",
    "CVE-2017-16845",
    "CVE-2017-17381",
    "CVE-2017-18043",
    "CVE-2018-10839",
    "CVE-2018-12617",
    "CVE-2018-17958",
    "CVE-2018-17963",
    "CVE-2019-8934",
    "CVE-2020-11947",
    "CVE-2020-13659",
    "CVE-2020-14394",
    "CVE-2020-15469",
    "CVE-2020-15859",
    "CVE-2020-25084",
    "CVE-2020-25624",
    "CVE-2020-25707",
    "CVE-2020-25723",
    "CVE-2020-25741",
    "CVE-2020-25743",
    "CVE-2020-27617",
    "CVE-2020-27821",
    "CVE-2021-3507",
    "CVE-2021-3527",
    "CVE-2021-3592",
    "CVE-2021-3593",
    "CVE-2021-3594",
    "CVE-2021-3595",
    "CVE-2021-3682",
    "CVE-2021-3735",
    "CVE-2021-3748",
    "CVE-2021-3750",
    "CVE-2021-3930",
    "CVE-2021-4145",
    "CVE-2021-4206",
    "CVE-2021-4207",
    "CVE-2022-4144",
    "CVE-2022-26353",
    "CVE-2022-26354",
    "CVE-2023-0664",
    "CVE-2023-3019",
    "CVE-2023-3301",
    "CVE-2023-5088",
    "CVE-2023-6693",
    "CVE-2024-3446",
    "CVE-2024-4693"
  );

  script_name(english:"RHEL 7 : qemu (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"description", value:
"This plugin has been deprecated as it does not adhere to established standards for this style of check.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-17963");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2017-16845");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/05/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-guest-agent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-ma");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:qemu-kvm-rhev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:spice-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:virtio-win");
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
