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
# extracted from Red Hat Security Advisory libtiff. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198563);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2017-17095",
    "CVE-2018-5360",
    "CVE-2018-10779",
    "CVE-2018-10801",
    "CVE-2018-16335",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-19210",
    "CVE-2019-6128",
    "CVE-2020-18768",
    "CVE-2020-19131",
    "CVE-2020-35521",
    "CVE-2020-35522",
    "CVE-2020-35523",
    "CVE-2020-35524",
    "CVE-2022-0865",
    "CVE-2022-0891",
    "CVE-2022-0924",
    "CVE-2022-1056",
    "CVE-2022-1354",
    "CVE-2022-2056",
    "CVE-2022-2057",
    "CVE-2022-2058",
    "CVE-2022-2519",
    "CVE-2022-2520",
    "CVE-2022-2521",
    "CVE-2022-2867",
    "CVE-2022-2868",
    "CVE-2022-2869",
    "CVE-2022-2953",
    "CVE-2022-3598",
    "CVE-2022-3599",
    "CVE-2022-3627",
    "CVE-2022-3970",
    "CVE-2022-4645",
    "CVE-2022-22844",
    "CVE-2022-40090",
    "CVE-2022-48281",
    "CVE-2023-0795",
    "CVE-2023-0796",
    "CVE-2023-0797",
    "CVE-2023-0798",
    "CVE-2023-0799",
    "CVE-2023-0800",
    "CVE-2023-0801",
    "CVE-2023-0802",
    "CVE-2023-0803",
    "CVE-2023-0804",
    "CVE-2023-1916",
    "CVE-2023-3164",
    "CVE-2023-3316",
    "CVE-2023-3576",
    "CVE-2023-3618",
    "CVE-2023-6277",
    "CVE-2023-25433",
    "CVE-2023-25434",
    "CVE-2023-25435",
    "CVE-2023-26965",
    "CVE-2023-26966",
    "CVE-2023-30086",
    "CVE-2023-30774",
    "CVE-2023-30775",
    "CVE-2023-40745",
    "CVE-2023-41175",
    "CVE-2023-52355",
    "CVE-2023-52356"
  );

  script_name(english:"RHEL 8 : libtiff (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-6228.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5038e510");
  # https://security.access.redhat.com/data/csaf/v2/vex/2017/cve-2017-17973.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8057caca");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-35524");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2023-25434");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/12/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:compat-libtiff3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:mingw-libtiff");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
