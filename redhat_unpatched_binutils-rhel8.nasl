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
# extracted from Red Hat Security Advisory binutils. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(200030);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2018-6872",
    "CVE-2018-10535",
    "CVE-2018-12641",
    "CVE-2018-12697",
    "CVE-2018-12698",
    "CVE-2018-12700",
    "CVE-2018-12934",
    "CVE-2018-13033",
    "CVE-2018-17358",
    "CVE-2018-17360",
    "CVE-2018-17794",
    "CVE-2018-17985",
    "CVE-2018-18309",
    "CVE-2018-18483",
    "CVE-2018-18484",
    "CVE-2018-18605",
    "CVE-2018-18606",
    "CVE-2018-18607",
    "CVE-2018-18700",
    "CVE-2018-18701",
    "CVE-2018-19932",
    "CVE-2018-20002",
    "CVE-2018-20623",
    "CVE-2018-20651",
    "CVE-2018-20671",
    "CVE-2019-9071",
    "CVE-2019-12972",
    "CVE-2019-17451",
    "CVE-2020-16598",
    "CVE-2020-35448",
    "CVE-2020-35493",
    "CVE-2020-35494",
    "CVE-2020-35495",
    "CVE-2020-35496",
    "CVE-2020-35507",
    "CVE-2021-3487",
    "CVE-2022-38533",
    "CVE-2023-1972",
    "CVE-2023-25584",
    "CVE-2023-25585",
    "CVE-2023-25588"
  );

  script_name(english:"RHEL 8 : binutils (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-20294.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?0b158823");
  # https://security.access.redhat.com/data/csaf/v2/vex/2018/cve-2018-1000876.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1b2bd6ac");
  # https://security.access.redhat.com/data/csaf/v2/vex/2021/cve-2021-45078.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27d03552");
  # https://security.access.redhat.com/data/csaf/v2/vex/2019/cve-2019-9075.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c41ce630");
  # https://security.access.redhat.com/data/csaf/v2/vex/2018/cve-2018-12699.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d3e7f789");
  # https://security.access.redhat.com/data/csaf/v2/vex/2019/cve-2019-9077.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4d2849b");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-18483");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-10-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-11-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-12-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:gcc-toolset-9-binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw-binutils");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
