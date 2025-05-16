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
  script_id(198513);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2014-8128",
    "CVE-2016-3186",
    "CVE-2016-3622",
    "CVE-2016-3624",
    "CVE-2016-3631",
    "CVE-2016-5102",
    "CVE-2016-5318",
    "CVE-2016-5319",
    "CVE-2016-5321",
    "CVE-2016-5323",
    "CVE-2016-9273",
    "CVE-2016-9297",
    "CVE-2016-9453",
    "CVE-2016-9532",
    "CVE-2016-9538",
    "CVE-2016-9539",
    "CVE-2016-10092",
    "CVE-2016-10093",
    "CVE-2016-10094",
    "CVE-2016-10266",
    "CVE-2016-10267",
    "CVE-2016-10268",
    "CVE-2016-10269",
    "CVE-2016-10270",
    "CVE-2016-10271",
    "CVE-2016-10272",
    "CVE-2017-5225",
    "CVE-2017-5563",
    "CVE-2017-7592",
    "CVE-2017-7593",
    "CVE-2017-7594",
    "CVE-2017-7595",
    "CVE-2017-7596",
    "CVE-2017-7597",
    "CVE-2017-7598",
    "CVE-2017-7599",
    "CVE-2017-7600",
    "CVE-2017-7601",
    "CVE-2017-7602",
    "CVE-2017-9117",
    "CVE-2017-9403",
    "CVE-2017-9404",
    "CVE-2017-9815",
    "CVE-2017-9935",
    "CVE-2017-9936",
    "CVE-2017-9937",
    "CVE-2017-10688",
    "CVE-2017-11335",
    "CVE-2017-12944",
    "CVE-2017-13726",
    "CVE-2017-13727",
    "CVE-2017-16232",
    "CVE-2017-17095",
    "CVE-2017-17942",
    "CVE-2018-5360",
    "CVE-2018-5784",
    "CVE-2018-7456",
    "CVE-2018-8905",
    "CVE-2018-10779",
    "CVE-2018-10801",
    "CVE-2018-12900",
    "CVE-2018-16335",
    "CVE-2018-17100",
    "CVE-2018-17101",
    "CVE-2018-18661",
    "CVE-2018-19210",
    "CVE-2019-6128",
    "CVE-2019-14973"
  );

  script_name(english:"RHEL 6 : libtiff (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  # https://security.access.redhat.com/data/csaf/v2/vex/2023/cve-2023-6228.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5038e510");
  # https://security.access.redhat.com/data/csaf/v2/vex/2017/cve-2017-17973.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8057caca");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2017-9117");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:libtiff");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
