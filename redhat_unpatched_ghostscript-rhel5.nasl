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
# extracted from Red Hat Security Advisory ghostscript. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(198835);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/02/18");

  script_cve_id(
    "CVE-2013-5653",
    "CVE-2015-3228",
    "CVE-2016-7977",
    "CVE-2016-7979",
    "CVE-2016-8602",
    "CVE-2016-10217",
    "CVE-2016-10218",
    "CVE-2016-10219",
    "CVE-2016-10220",
    "CVE-2016-10317",
    "CVE-2017-5951",
    "CVE-2017-7207",
    "CVE-2017-7885",
    "CVE-2017-8291",
    "CVE-2017-8908",
    "CVE-2017-9216",
    "CVE-2017-9610",
    "CVE-2017-9611",
    "CVE-2017-9612",
    "CVE-2017-9618",
    "CVE-2017-9619",
    "CVE-2017-9620",
    "CVE-2017-9726",
    "CVE-2017-9727",
    "CVE-2017-9739",
    "CVE-2017-9740",
    "CVE-2017-9835",
    "CVE-2017-11714",
    "CVE-2018-10194",
    "CVE-2018-11645",
    "CVE-2018-15908",
    "CVE-2018-15909",
    "CVE-2018-15910",
    "CVE-2018-15911",
    "CVE-2018-16509",
    "CVE-2018-16511",
    "CVE-2018-16539",
    "CVE-2018-16540",
    "CVE-2018-16541",
    "CVE-2018-16542",
    "CVE-2018-17183",
    "CVE-2018-17961",
    "CVE-2018-18073",
    "CVE-2018-18284",
    "CVE-2018-19134",
    "CVE-2018-19409",
    "CVE-2018-19475",
    "CVE-2018-19476",
    "CVE-2018-19477",
    "CVE-2018-19478",
    "CVE-2019-3835",
    "CVE-2019-3838",
    "CVE-2019-6116"
  );
  script_xref(name:"CISA-KNOWN-EXPLOITED", value:"2022/06/14");

  script_name(english:"RHEL 5 : ghostscript (Unpatched Vulnerability) (deprecated)");

  script_set_attribute(attribute:"synopsis", value: "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"description", value:
"Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
  script_set_attribute(attribute:"solution", value: "n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:H/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-16509");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2018-19409");

  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Ghostscript Failed Restore Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"vendor_unpatched", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2024/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:ghostscript");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2024-2025 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}

exit(0, "Plugin has been deprecated due to a change in logic. Coverage will be provided in a new plugin.");
