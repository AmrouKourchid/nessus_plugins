#%NASL_MIN_LEVEL 80900
##
# (C) Tenable, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2025:4576. The text
# itself is copyright (C) Red Hat, Inc.
##

include('compat.inc');

if (description)
{
  script_id(235426);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2025/05/07");

  script_cve_id(
    "CVE-2024-56326",
    "CVE-2024-56374",
    "CVE-2025-27407",
    "CVE-2025-27610"
  );
  script_xref(name:"RHSA", value:"2025:4576");

  script_name(english:"RHEL 9 : Satellite 6.17.0  (Important) (RHSA-2025:4576)");

  script_set_attribute(attribute:"synopsis", value:
"The remote Red Hat host is missing one or more security updates.");
  script_set_attribute(attribute:"description", value:
"The remote Redhat Enterprise Linux 9 host has packages installed that are affected by multiple vulnerabilities as
referenced in the RHSA-2025:4576 advisory.

    Red Hat Satellite is a system management solution that allows organizations to
    configure and maintain their systems without the necessity to provide public
    Internet access to their servers or other client systems. It performs
    provisioning and configuration management of predefined standard operating
    environments.

    Security Fix(es):
    * python-django: Potential denial-of-service vulnerability in IPv6 validation (CVE-2024-56374)
    * python-jinja2: Sandbox breakout through indirect reference to format method (CVE-2024-56326)
    * rubygem-rack: Local File Inclusion in Rack::Static (CVE-2025-27610)
    * rubygem-graphql: Remote code execution when loading a crafted GraphQL schema (CVE-2025-27407)

Tenable has extracted the preceding description block directly from the Red Hat Enterprise Linux security advisory.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/security/updates/classification/#important");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-12130");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16243");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16248");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-16392");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-17448");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-17783");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19325");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19336");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19505");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19515");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19781");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-19933");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20010");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20579");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-20586");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-21359");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22510");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-22966");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23114");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23229");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-2340");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-23647");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24108");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24282");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24725");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-24795");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25448");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25464");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-2549");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-25949");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26058");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26076");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26522");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26537");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26605");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26741");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-26866");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27070");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27153");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27221");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27308");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27349");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27369");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27374");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27388");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27418");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27420");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27427");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27554");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27620");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27627");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27675");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27703");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27717");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27756");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27847");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27863");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27874");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27875");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27924");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27939");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-27979");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28029");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28060");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28185");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28216");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28293");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28311");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28312");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28337");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28338");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28356");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28443");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28464");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28471");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28472");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28486");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28493");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28526");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28538");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28552");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28553");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28556");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28575");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28613");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28662");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28735");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28743");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28756");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28818");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28823");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28826");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28856");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28894");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28981");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-28994");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29017");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29058");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29062");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29068");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29070");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29090");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29203");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29209");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29212");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29214");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29314");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29322");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29332");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29345");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29347");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29454");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29469");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29567");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29596");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29622");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29623");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29667");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29670");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29675");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29679");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29794");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29863");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29939");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29945");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29950");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-29957");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30004");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30014");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30043");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30070");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30098");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30102");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30106");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30108");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30112");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30118");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30138");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30141");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30152");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30154");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30167");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30172");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30176");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30186");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30188");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30209");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30220");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30227");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30228");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30314");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30342");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30374");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30378");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30403");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30443");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30464");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30491");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30541");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30543");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30544");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30577");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30611");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30614");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30625");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30636");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30637");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30669");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30686");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30715");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30717");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30726");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30761");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30767");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30785");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30790");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30815");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30841");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30846");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30869");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30916");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30961");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30962");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30967");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-30970");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31040");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31105");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31111");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31157");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31160");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31193");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31196");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31203");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31220");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31241");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31308");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31315");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31316");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31338");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31351");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31398");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31451");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31475");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31479");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31502");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31526");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31588");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31602");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31645");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31813");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-31814");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-32426");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-32447");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-32467");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-32604");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-32605");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-5118");
  script_set_attribute(attribute:"see_also", value:"https://issues.redhat.com/browse/SAT-6776");
  # https://security.access.redhat.com/data/csaf/v2/advisories/2025/rhsa-2025_4576.json
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?393acc71");
  script_set_attribute(attribute:"see_also", value:"https://access.redhat.com/errata/RHSA-2025:4576");
  script_set_attribute(attribute:"solution", value:
"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss4_vector", value:"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N");
  script_set_attribute(attribute:"cvss4_threat_vector", value:"CVSS:4.0/E:U");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2025-27610");
  script_set_attribute(attribute:"cvss3_score_source", value:"CVE-2025-27407");
  script_set_attribute(attribute:"cvss4_score_source", value:"CVE-2024-56326");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(23, 94, 693, 770);
  script_set_attribute(attribute:"vendor_severity", value:"Important");

  script_set_attribute(attribute:"vuln_publication_date", value:"2024/12/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2025/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2025/05/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-django");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:python3.11-jinja2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-graphql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:rubygem-rack");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2025 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl", "redhat_repos.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include('rpm.inc');
include('rhel.inc');

if (!get_kb_item('Host/local_checks_enabled')) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
var os_release = get_kb_item('Host/RedHat/release');
if (isnull(os_release) || 'Red Hat' >!< os_release) audit(AUDIT_OS_NOT, 'Red Hat');
var os_ver = pregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:os_release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, 'Red Hat');
os_ver = os_ver[1];
if (!rhel_check_release(operator: 'ge', os_version: os_ver, rhel_version: '9')) audit(AUDIT_OS_NOT, 'Red Hat 9.x', 'Red Hat ' + os_ver);

if (!get_kb_item('Host/RedHat/rpm-list')) audit(AUDIT_PACKAGE_LIST_MISSING);

var cpu = get_kb_item('Host/cpu');
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ('x86_64' >!< cpu && cpu !~ "^i[3-6]86$" && 's390' >!< cpu && 'aarch64' >!< cpu && 'ppc' >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, 'Red Hat', cpu);

var constraints = [
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.17/debug',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.17/os',
      'content/dist/layered/rhel9/x86_64/sat-capsule/6.17/source/SRPMS',
      'content/dist/layered/rhel9/x86_64/satellite/6.17/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.17/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.17/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'python3.11-django-4.2.19-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-56374']},
      {'reference':'python3.11-jinja2-3.1.5-1.el9pc', 'release':'9', 'el_string':'el9pc', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2024-56326']},
      {'reference':'rubygem-rack-2.2.13-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2025-27610']}
    ]
  },
  {
    'repo_relative_urls': [
      'content/dist/layered/rhel9/x86_64/satellite/6.17/debug',
      'content/dist/layered/rhel9/x86_64/satellite/6.17/os',
      'content/dist/layered/rhel9/x86_64/satellite/6.17/source/SRPMS'
    ],
    'pkgs': [
      {'reference':'rubygem-graphql-1.13.24-1.el9sat', 'release':'9', 'el_string':'el9sat', 'rpm_spec_vers_cmp':TRUE, 'exists_check':'satellite-6', 'cves':['CVE-2025-27407']}
    ]
  }
];

var applicable_repo_urls = rhel_determine_applicable_repository_urls(constraints:constraints);
if(applicable_repo_urls == RHEL_REPOS_NO_OVERLAP_MESSAGE) exit(0, RHEL_REPO_NOT_ENABLED);

var flag = 0;
foreach var constraint_array ( constraints ) {
  var repo_relative_urls = NULL;
  if (!empty_or_null(constraint_array['repo_relative_urls'])) repo_relative_urls = constraint_array['repo_relative_urls'];
  foreach var pkg ( constraint_array['pkgs'] ) {
    var reference = NULL;
    var _release = NULL;
    var sp = NULL;
    var _cpu = NULL;
    var el_string = NULL;
    var rpm_spec_vers_cmp = NULL;
    var epoch = NULL;
    var allowmaj = NULL;
    var exists_check = NULL;
    var cves = NULL;
    if (!empty_or_null(pkg['reference'])) reference = pkg['reference'];
    if (!empty_or_null(pkg['release'])) _release = 'RHEL' + pkg['release'];
    if (!empty_or_null(pkg['sp'])) sp = pkg['sp'];
    if (!empty_or_null(pkg['cpu'])) _cpu = pkg['cpu'];
    if (!empty_or_null(pkg['el_string'])) el_string = pkg['el_string'];
    if (!empty_or_null(pkg['rpm_spec_vers_cmp'])) rpm_spec_vers_cmp = pkg['rpm_spec_vers_cmp'];
    if (!empty_or_null(pkg['epoch'])) epoch = pkg['epoch'];
    if (!empty_or_null(pkg['allowmaj'])) allowmaj = pkg['allowmaj'];
    if (!empty_or_null(pkg['exists_check'])) exists_check = pkg['exists_check'];
    if (!empty_or_null(pkg['cves'])) cves = pkg['cves'];
    if (reference &&
        _release &&
        rhel_decide_repo_relative_url_check(required_repo_url_list:repo_relative_urls) &&
        (applicable_repo_urls || (!exists_check || rpm_exists(release:_release, rpm:exists_check))) &&
        rpm_check(release:_release, sp:sp, cpu:_cpu, reference:reference, epoch:epoch, el_string:el_string, rpm_spec_vers_cmp:rpm_spec_vers_cmp, allowmaj:allowmaj, cves:cves)) flag++;
  }
}

if (flag)
{
  var extra = NULL;
  if (isnull(applicable_repo_urls) || !applicable_repo_urls) extra = rpm_report_get() + redhat_report_repo_caveat();
  else extra = rpm_report_get();
  security_report_v4(
      port       : 0,
      severity   : SECURITY_HOLE,
      extra      : extra
  );
  exit(0);
}
else
{
  var tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, 'python3.11-django / python3.11-jinja2 / rubygem-graphql / etc');
}
