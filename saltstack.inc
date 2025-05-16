#
# (C) Tenable Network Security, Inc.
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security Inc.
#
#
# @NOGPL@
#
# saltstack.inc
# Revision: 1.1
#

##
# Determines if the saltstack package comes from an OS repo
# Packages from SaltStack repo do not include ubuntu or deb
# and these distros include their own backport versions in some
# instances. SaltStack repo DOES include RH/CentOS in their 
# package names, but those distro's repos don't include SaltStack.
# 
# return: TRUE: managed by OS package manager
#         FALSE: managed by non-OS package manager
##
function is_salt_package_managed(pkg)
{
  return preg(pattern:"(deb|ubuntu)\d+", string:pkg['path_package']);
}
