#
# export_vars.sh
#
# This shell script is used to export vars to the application using the
# APRUTIL library. This script should be "sourced" to ensure the variable
# values are set within the calling script's context. For example:
#
#   $ . path/to/apr-util/export_vars.sh
#

APRUTIL_EXPORT_INCLUDES="-I/home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr-util/xml/expat/lib"
APRUTIL_EXPORT_LIBS="/home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr-util/xml/expat/libexpat.la"
APRUTIL_LDFLAGS=""
