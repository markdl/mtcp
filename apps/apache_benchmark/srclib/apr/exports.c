/*
 * THIS FILE WAS AUTOGENERATED BY make_exports.awk
 *
 * This is an ugly hack that needs to be here, so
 * that libtool will link all of the APR functions
 * into server regardless of whether the base server
 * uses them.
 */

#define CORE_PRIVATE

#include "apr_allocator.h"
#include "apr_atomic.h"
#include "apr_dso.h"
#include "apr_env.h"
#include "apr_errno.h"
#include "apr_file_info.h"
#include "apr_file_io.h"
#include "apr_fnmatch.h"
#include "apr_general.h"
#include "apr_getopt.h"
#include "apr_global_mutex.h"
#include "apr_hash.h"
#include "apr_inherit.h"
#include "apr_lib.h"
#include "apr_mmap.h"
#include "apr_network_io.h"
#include "apr_poll.h"
#include "apr_pools.h"
#include "apr_portable.h"
#include "apr_proc_mutex.h"
#include "apr_random.h"
#include "apr_ring.h"
#include "apr_shm.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_support.h"
#include "apr_tables.h"
#include "apr_thread_cond.h"
#include "apr_thread_mutex.h"
#include "apr_thread_proc.h"
#include "apr_thread_rwlock.h"
#include "apr_time.h"
#include "apr_user.h"
#include "apr_version.h"
#include "apr_want.h"

const void *ap_ugly_hack = NULL;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_allocator.h
 */
const void *ap_hack_apr_allocator_create = (const void *)apr_allocator_create;
const void *ap_hack_apr_allocator_destroy = (const void *)apr_allocator_destroy;
const void *ap_hack_apr_allocator_alloc = (const void *)apr_allocator_alloc;
const void *ap_hack_apr_allocator_free = (const void *)apr_allocator_free;
const void *ap_hack_apr_allocator_owner_set = (const void *)apr_allocator_owner_set;
const void *ap_hack_apr_allocator_owner_get = (const void *)apr_allocator_owner_get;
const void *ap_hack_apr_allocator_max_free_set = (const void *)apr_allocator_max_free_set;
#if APR_HAS_THREADS
const void *ap_hack_apr_allocator_mutex_set = (const void *)apr_allocator_mutex_set;
const void *ap_hack_apr_allocator_mutex_get = (const void *)apr_allocator_mutex_get;
#endif /* APR_HAS_THREADS */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_atomic.h
 */
const void *ap_hack_apr_atomic_init = (const void *)apr_atomic_init;
const void *ap_hack_apr_atomic_read32 = (const void *)apr_atomic_read32;
const void *ap_hack_apr_atomic_set32 = (const void *)apr_atomic_set32;
const void *ap_hack_apr_atomic_add32 = (const void *)apr_atomic_add32;
const void *ap_hack_apr_atomic_sub32 = (const void *)apr_atomic_sub32;
const void *ap_hack_apr_atomic_inc32 = (const void *)apr_atomic_inc32;
const void *ap_hack_apr_atomic_dec32 = (const void *)apr_atomic_dec32;
const void *ap_hack_apr_atomic_cas32 = (const void *)apr_atomic_cas32;
const void *ap_hack_apr_atomic_xchg32 = (const void *)apr_atomic_xchg32;
const void *ap_hack_apr_atomic_casptr = (const void *)apr_atomic_casptr;
const void *ap_hack_apr_atomic_xchgptr = (const void *)apr_atomic_xchgptr;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_dso.h
 */
#if APR_HAS_DSO || defined(DOXYGEN)
const void *ap_hack_apr_dso_load = (const void *)apr_dso_load;
const void *ap_hack_apr_dso_unload = (const void *)apr_dso_unload;
const void *ap_hack_apr_dso_sym = (const void *)apr_dso_sym;
const void *ap_hack_apr_dso_error = (const void *)apr_dso_error;
#endif /* APR_HAS_DSO */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_env.h
 */
const void *ap_hack_apr_env_get = (const void *)apr_env_get;
const void *ap_hack_apr_env_set = (const void *)apr_env_set;
const void *ap_hack_apr_env_delete = (const void *)apr_env_delete;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_errno.h
 */
const void *ap_hack_apr_strerror = (const void *)apr_strerror;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_file_info.h
 */
const void *ap_hack_apr_stat = (const void *)apr_stat;
const void *ap_hack_apr_dir_open = (const void *)apr_dir_open;
const void *ap_hack_apr_dir_close = (const void *)apr_dir_close;
const void *ap_hack_apr_dir_read = (const void *)apr_dir_read;
const void *ap_hack_apr_dir_rewind = (const void *)apr_dir_rewind;
const void *ap_hack_apr_filepath_root = (const void *)apr_filepath_root;
const void *ap_hack_apr_filepath_merge = (const void *)apr_filepath_merge;
const void *ap_hack_apr_filepath_list_split = (const void *)apr_filepath_list_split;
const void *ap_hack_apr_filepath_list_merge = (const void *)apr_filepath_list_merge;
const void *ap_hack_apr_filepath_get = (const void *)apr_filepath_get;
const void *ap_hack_apr_filepath_set = (const void *)apr_filepath_set;
const void *ap_hack_apr_filepath_encoding = (const void *)apr_filepath_encoding;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_file_io.h
 */
const void *ap_hack_apr_file_open = (const void *)apr_file_open;
const void *ap_hack_apr_file_close = (const void *)apr_file_close;
const void *ap_hack_apr_file_remove = (const void *)apr_file_remove;
const void *ap_hack_apr_file_rename = (const void *)apr_file_rename;
const void *ap_hack_apr_file_link = (const void *)apr_file_link;
const void *ap_hack_apr_file_copy = (const void *)apr_file_copy;
const void *ap_hack_apr_file_append = (const void *)apr_file_append;
const void *ap_hack_apr_file_eof = (const void *)apr_file_eof;
const void *ap_hack_apr_file_open_stderr = (const void *)apr_file_open_stderr;
const void *ap_hack_apr_file_open_stdout = (const void *)apr_file_open_stdout;
const void *ap_hack_apr_file_open_stdin = (const void *)apr_file_open_stdin;
const void *ap_hack_apr_file_open_flags_stderr = (const void *)apr_file_open_flags_stderr;
const void *ap_hack_apr_file_open_flags_stdout = (const void *)apr_file_open_flags_stdout;
const void *ap_hack_apr_file_open_flags_stdin = (const void *)apr_file_open_flags_stdin;
const void *ap_hack_apr_file_read = (const void *)apr_file_read;
const void *ap_hack_apr_file_write = (const void *)apr_file_write;
const void *ap_hack_apr_file_writev = (const void *)apr_file_writev;
const void *ap_hack_apr_file_read_full = (const void *)apr_file_read_full;
const void *ap_hack_apr_file_write_full = (const void *)apr_file_write_full;
const void *ap_hack_apr_file_writev_full = (const void *)apr_file_writev_full;
const void *ap_hack_apr_file_putc = (const void *)apr_file_putc;
const void *ap_hack_apr_file_getc = (const void *)apr_file_getc;
const void *ap_hack_apr_file_ungetc = (const void *)apr_file_ungetc;
const void *ap_hack_apr_file_gets = (const void *)apr_file_gets;
const void *ap_hack_apr_file_puts = (const void *)apr_file_puts;
const void *ap_hack_apr_file_flush = (const void *)apr_file_flush;
const void *ap_hack_apr_file_sync = (const void *)apr_file_sync;
const void *ap_hack_apr_file_datasync = (const void *)apr_file_datasync;
const void *ap_hack_apr_file_dup = (const void *)apr_file_dup;
const void *ap_hack_apr_file_dup2 = (const void *)apr_file_dup2;
const void *ap_hack_apr_file_setaside = (const void *)apr_file_setaside;
const void *ap_hack_apr_file_buffer_set = (const void *)apr_file_buffer_set;
const void *ap_hack_apr_file_buffer_size_get = (const void *)apr_file_buffer_size_get;
const void *ap_hack_apr_file_seek = (const void *)apr_file_seek;
const void *ap_hack_apr_file_pipe_create = (const void *)apr_file_pipe_create;
const void *ap_hack_apr_file_pipe_create_ex = (const void *)apr_file_pipe_create_ex;
const void *ap_hack_apr_file_namedpipe_create = (const void *)apr_file_namedpipe_create;
const void *ap_hack_apr_file_pipe_timeout_get = (const void *)apr_file_pipe_timeout_get;
const void *ap_hack_apr_file_pipe_timeout_set = (const void *)apr_file_pipe_timeout_set;
const void *ap_hack_apr_file_lock = (const void *)apr_file_lock;
const void *ap_hack_apr_file_unlock = (const void *)apr_file_unlock;
const void *ap_hack_apr_file_name_get = (const void *)apr_file_name_get;
const void *ap_hack_apr_file_data_get = (const void *)apr_file_data_get;
const void *ap_hack_apr_file_data_set = (const void *)apr_file_data_set;
const void *ap_hack_apr_file_printf = (const void *)apr_file_printf;
const void *ap_hack_apr_file_perms_set = (const void *)apr_file_perms_set;
const void *ap_hack_apr_file_attrs_set = (const void *)apr_file_attrs_set;
const void *ap_hack_apr_file_mtime_set = (const void *)apr_file_mtime_set;
const void *ap_hack_apr_dir_make = (const void *)apr_dir_make;
const void *ap_hack_apr_dir_make_recursive = (const void *)apr_dir_make_recursive;
const void *ap_hack_apr_dir_remove = (const void *)apr_dir_remove;
const void *ap_hack_apr_file_info_get = (const void *)apr_file_info_get;
const void *ap_hack_apr_file_trunc = (const void *)apr_file_trunc;
const void *ap_hack_apr_file_flags_get = (const void *)apr_file_flags_get;
const void *ap_hack_apr_file_pool_get = (const void *)apr_file_pool_get;
const void *ap_hack_apr_file_inherit_set = (const void *)apr_file_inherit_set;
const void *ap_hack_apr_file_inherit_unset = (const void *)apr_file_inherit_unset;
const void *ap_hack_apr_file_mktemp = (const void *)apr_file_mktemp;
const void *ap_hack_apr_temp_dir_get = (const void *)apr_temp_dir_get;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_fnmatch.h
 */
const void *ap_hack_apr_fnmatch = (const void *)apr_fnmatch;
const void *ap_hack_apr_fnmatch_test = (const void *)apr_fnmatch_test;
const void *ap_hack_apr_match_glob = (const void *)apr_match_glob;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_general.h
 */
const void *ap_hack_apr_initialize = (const void *)apr_initialize;
const void *ap_hack_apr_app_initialize = (const void *)apr_app_initialize;
const void *ap_hack_apr_terminate = (const void *)apr_terminate;
const void *ap_hack_apr_terminate2 = (const void *)apr_terminate2;
#if APR_HAS_RANDOM || defined(DOXYGEN)
const void *ap_hack_apr_generate_random_bytes = (const void *)apr_generate_random_bytes;
#endif

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_getopt.h
 */
const void *ap_hack_apr_getopt_init = (const void *)apr_getopt_init;
const void *ap_hack_apr_getopt = (const void *)apr_getopt;
const void *ap_hack_apr_getopt_long = (const void *)apr_getopt_long;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_global_mutex.h
 */
#if !APR_PROC_MUTEX_IS_GLOBAL || defined(DOXYGEN)
const void *ap_hack_apr_global_mutex_create = (const void *)apr_global_mutex_create;
const void *ap_hack_apr_global_mutex_child_init = (const void *)apr_global_mutex_child_init;
const void *ap_hack_apr_global_mutex_lock = (const void *)apr_global_mutex_lock;
const void *ap_hack_apr_global_mutex_trylock = (const void *)apr_global_mutex_trylock;
const void *ap_hack_apr_global_mutex_unlock = (const void *)apr_global_mutex_unlock;
const void *ap_hack_apr_global_mutex_destroy = (const void *)apr_global_mutex_destroy;
const void *ap_hack_apr_global_mutex_lockfile = (const void *)apr_global_mutex_lockfile;
const void *ap_hack_apr_global_mutex_name = (const void *)apr_global_mutex_name;
const void *ap_hack_apr_global_mutex_pool_get = (const void *)apr_global_mutex_pool_get;
#else /* APR_PROC_MUTEX_IS_GLOBAL */
#endif

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_hash.h
 */
const void *ap_hack_apr_hashfunc_default = (const void *)apr_hashfunc_default;
const void *ap_hack_apr_hash_make = (const void *)apr_hash_make;
const void *ap_hack_apr_hash_make_custom = (const void *)apr_hash_make_custom;
const void *ap_hack_apr_hash_copy = (const void *)apr_hash_copy;
const void *ap_hack_apr_hash_set = (const void *)apr_hash_set;
const void *ap_hack_apr_hash_get = (const void *)apr_hash_get;
const void *ap_hack_apr_hash_first = (const void *)apr_hash_first;
const void *ap_hack_apr_hash_next = (const void *)apr_hash_next;
const void *ap_hack_apr_hash_this = (const void *)apr_hash_this;
const void *ap_hack_apr_hash_count = (const void *)apr_hash_count;
const void *ap_hack_apr_hash_clear = (const void *)apr_hash_clear;
const void *ap_hack_apr_hash_overlay = (const void *)apr_hash_overlay;
const void *ap_hack_apr_hash_merge = (const void *)apr_hash_merge;
const void *ap_hack_apr_hash_do = (const void *)apr_hash_do;
const void *ap_hack_apr_hash_pool_get = (const void *)apr_hash_pool_get;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_lib.h
 */
const void *ap_hack_apr_filepath_name_get = (const void *)apr_filepath_name_get;
const void *ap_hack_apr_vformatter = (const void *)apr_vformatter;
const void *ap_hack_apr_password_get = (const void *)apr_password_get;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_mmap.h
 */
#if APR_HAS_MMAP || defined(DOXYGEN)
const void *ap_hack_apr_mmap_create = (const void *)apr_mmap_create;
const void *ap_hack_apr_mmap_dup = (const void *)apr_mmap_dup;
const void *ap_hack_apr_mmap_delete = (const void *)apr_mmap_delete;
const void *ap_hack_apr_mmap_offset = (const void *)apr_mmap_offset;
#endif /* APR_HAS_MMAP */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_network_io.h
 */
const void *ap_hack_apr_socket_create = (const void *)apr_socket_create;
const void *ap_hack_apr_socket_shutdown = (const void *)apr_socket_shutdown;
const void *ap_hack_apr_socket_close = (const void *)apr_socket_close;
const void *ap_hack_apr_socket_bind = (const void *)apr_socket_bind;
const void *ap_hack_apr_socket_listen = (const void *)apr_socket_listen;
const void *ap_hack_apr_socket_accept = (const void *)apr_socket_accept;
const void *ap_hack_apr_socket_connect = (const void *)apr_socket_connect;
const void *ap_hack_apr_socket_atreadeof = (const void *)apr_socket_atreadeof;
const void *ap_hack_apr_sockaddr_info_get = (const void *)apr_sockaddr_info_get;
const void *ap_hack_apr_getnameinfo = (const void *)apr_getnameinfo;
const void *ap_hack_apr_parse_addr_port = (const void *)apr_parse_addr_port;
const void *ap_hack_apr_gethostname = (const void *)apr_gethostname;
const void *ap_hack_apr_socket_data_get = (const void *)apr_socket_data_get;
const void *ap_hack_apr_socket_data_set = (const void *)apr_socket_data_set;
const void *ap_hack_apr_socket_send = (const void *)apr_socket_send;
const void *ap_hack_apr_socket_sendv = (const void *)apr_socket_sendv;
const void *ap_hack_apr_socket_sendto = (const void *)apr_socket_sendto;
const void *ap_hack_apr_socket_recvfrom = (const void *)apr_socket_recvfrom;
#if APR_HAS_SENDFILE || defined(DOXYGEN)
const void *ap_hack_apr_socket_sendfile = (const void *)apr_socket_sendfile;
#endif /* APR_HAS_SENDFILE */
const void *ap_hack_apr_socket_recv = (const void *)apr_socket_recv;
const void *ap_hack_apr_socket_opt_set = (const void *)apr_socket_opt_set;
const void *ap_hack_apr_socket_timeout_set = (const void *)apr_socket_timeout_set;
const void *ap_hack_apr_socket_opt_get = (const void *)apr_socket_opt_get;
const void *ap_hack_apr_socket_timeout_get = (const void *)apr_socket_timeout_get;
const void *ap_hack_apr_socket_atmark = (const void *)apr_socket_atmark;
const void *ap_hack_apr_socket_addr_get = (const void *)apr_socket_addr_get;
const void *ap_hack_apr_sockaddr_ip_get = (const void *)apr_sockaddr_ip_get;
const void *ap_hack_apr_sockaddr_ip_getbuf = (const void *)apr_sockaddr_ip_getbuf;
const void *ap_hack_apr_sockaddr_equal = (const void *)apr_sockaddr_equal;
const void *ap_hack_apr_socket_type_get = (const void *)apr_socket_type_get;
const void *ap_hack_apr_getservbyname = (const void *)apr_getservbyname;
const void *ap_hack_apr_ipsubnet_create = (const void *)apr_ipsubnet_create;
const void *ap_hack_apr_ipsubnet_test = (const void *)apr_ipsubnet_test;
const void *ap_hack_apr_socket_protocol_get = (const void *)apr_socket_protocol_get;
const void *ap_hack_apr_socket_pool_get = (const void *)apr_socket_pool_get;
const void *ap_hack_apr_socket_inherit_set = (const void *)apr_socket_inherit_set;
const void *ap_hack_apr_socket_inherit_unset = (const void *)apr_socket_inherit_unset;
const void *ap_hack_apr_mcast_join = (const void *)apr_mcast_join;
const void *ap_hack_apr_mcast_leave = (const void *)apr_mcast_leave;
const void *ap_hack_apr_mcast_hops = (const void *)apr_mcast_hops;
const void *ap_hack_apr_mcast_loopback = (const void *)apr_mcast_loopback;
const void *ap_hack_apr_mcast_interface = (const void *)apr_mcast_interface;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_poll.h
 */
const void *ap_hack_apr_pollset_create = (const void *)apr_pollset_create;
const void *ap_hack_apr_pollset_create_ex = (const void *)apr_pollset_create_ex;
const void *ap_hack_apr_pollset_destroy = (const void *)apr_pollset_destroy;
const void *ap_hack_apr_pollset_add = (const void *)apr_pollset_add;
const void *ap_hack_apr_pollset_remove = (const void *)apr_pollset_remove;
const void *ap_hack_apr_pollset_poll = (const void *)apr_pollset_poll;
const void *ap_hack_apr_pollset_wakeup = (const void *)apr_pollset_wakeup;
const void *ap_hack_apr_poll = (const void *)apr_poll;
const void *ap_hack_apr_pollset_method_name = (const void *)apr_pollset_method_name;
const void *ap_hack_apr_poll_method_defname = (const void *)apr_poll_method_defname;
const void *ap_hack_apr_pollcb_create = (const void *)apr_pollcb_create;
const void *ap_hack_apr_pollcb_create_ex = (const void *)apr_pollcb_create_ex;
const void *ap_hack_apr_pollcb_add = (const void *)apr_pollcb_add;
const void *ap_hack_apr_pollcb_remove = (const void *)apr_pollcb_remove;
const void *ap_hack_apr_pollcb_poll = (const void *)apr_pollcb_poll;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_pools.h
 */
const void *ap_hack_apr_pool_initialize = (const void *)apr_pool_initialize;
const void *ap_hack_apr_pool_terminate = (const void *)apr_pool_terminate;
const void *ap_hack_apr_pool_create_ex = (const void *)apr_pool_create_ex;
const void *ap_hack_apr_pool_create_core_ex = (const void *)apr_pool_create_core_ex;
const void *ap_hack_apr_pool_create_unmanaged_ex = (const void *)apr_pool_create_unmanaged_ex;
const void *ap_hack_apr_pool_create_ex_debug = (const void *)apr_pool_create_ex_debug;
const void *ap_hack_apr_pool_create_core_ex_debug = (const void *)apr_pool_create_core_ex_debug;
const void *ap_hack_apr_pool_create_unmanaged_ex_debug = (const void *)apr_pool_create_unmanaged_ex_debug;
#if defined(DOXYGEN)
const void *ap_hack_apr_pool_create = (const void *)apr_pool_create;
#else
#endif
#if defined(DOXYGEN)
const void *ap_hack_apr_pool_create_core = (const void *)apr_pool_create_core;
const void *ap_hack_apr_pool_create_unmanaged = (const void *)apr_pool_create_unmanaged;
#else
#endif
const void *ap_hack_apr_pool_allocator_get = (const void *)apr_pool_allocator_get;
const void *ap_hack_apr_pool_clear = (const void *)apr_pool_clear;
const void *ap_hack_apr_pool_clear_debug = (const void *)apr_pool_clear_debug;
const void *ap_hack_apr_pool_destroy = (const void *)apr_pool_destroy;
const void *ap_hack_apr_pool_destroy_debug = (const void *)apr_pool_destroy_debug;
const void *ap_hack_apr_palloc = (const void *)apr_palloc;
const void *ap_hack_apr_palloc_debug = (const void *)apr_palloc_debug;
#if defined(DOXYGEN)
const void *ap_hack_apr_pcalloc = (const void *)apr_pcalloc;
#elif !APR_POOL_DEBUG
#endif
const void *ap_hack_apr_pcalloc_debug = (const void *)apr_pcalloc_debug;
const void *ap_hack_apr_pool_abort_set = (const void *)apr_pool_abort_set;
const void *ap_hack_apr_pool_abort_get = (const void *)apr_pool_abort_get;
const void *ap_hack_apr_pool_parent_get = (const void *)apr_pool_parent_get;
const void *ap_hack_apr_pool_is_ancestor = (const void *)apr_pool_is_ancestor;
const void *ap_hack_apr_pool_tag = (const void *)apr_pool_tag;
const void *ap_hack_apr_pool_userdata_set = (const void *)apr_pool_userdata_set;
const void *ap_hack_apr_pool_userdata_setn = (const void *)apr_pool_userdata_setn;
const void *ap_hack_apr_pool_userdata_get = (const void *)apr_pool_userdata_get;
const void *ap_hack_apr_pool_cleanup_register = (const void *)apr_pool_cleanup_register;
const void *ap_hack_apr_pool_pre_cleanup_register = (const void *)apr_pool_pre_cleanup_register;
const void *ap_hack_apr_pool_cleanup_kill = (const void *)apr_pool_cleanup_kill;
const void *ap_hack_apr_pool_child_cleanup_set = (const void *)apr_pool_child_cleanup_set;
const void *ap_hack_apr_pool_cleanup_run = (const void *)apr_pool_cleanup_run;
const void *ap_hack_apr_pool_cleanup_null = (const void *)apr_pool_cleanup_null;
const void *ap_hack_apr_pool_cleanup_for_exec = (const void *)apr_pool_cleanup_for_exec;
#if APR_POOL_DEBUG || defined(DOXYGEN)
const void *ap_hack_apr_pool_join = (const void *)apr_pool_join;
const void *ap_hack_apr_pool_find = (const void *)apr_pool_find;
const void *ap_hack_apr_pool_num_bytes = (const void *)apr_pool_num_bytes;
const void *ap_hack_apr_pool_lock = (const void *)apr_pool_lock;
#else /* APR_POOL_DEBUG or DOXYGEN */
#endif /* APR_POOL_DEBUG or DOXYGEN */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_portable.h
 */
#if APR_PROC_MUTEX_IS_GLOBAL || defined(DOXYGEN)
#else
const void *ap_hack_apr_os_global_mutex_get = (const void *)apr_os_global_mutex_get;
#endif
const void *ap_hack_apr_os_file_get = (const void *)apr_os_file_get;
const void *ap_hack_apr_os_dir_get = (const void *)apr_os_dir_get;
const void *ap_hack_apr_os_sock_get = (const void *)apr_os_sock_get;
const void *ap_hack_apr_os_proc_mutex_get = (const void *)apr_os_proc_mutex_get;
const void *ap_hack_apr_os_exp_time_get = (const void *)apr_os_exp_time_get;
const void *ap_hack_apr_os_imp_time_get = (const void *)apr_os_imp_time_get;
const void *ap_hack_apr_os_shm_get = (const void *)apr_os_shm_get;
#if APR_HAS_THREADS || defined(DOXYGEN)
const void *ap_hack_apr_os_thread_get = (const void *)apr_os_thread_get;
const void *ap_hack_apr_os_threadkey_get = (const void *)apr_os_threadkey_get;
const void *ap_hack_apr_os_thread_put = (const void *)apr_os_thread_put;
const void *ap_hack_apr_os_threadkey_put = (const void *)apr_os_threadkey_put;
const void *ap_hack_apr_os_thread_current = (const void *)apr_os_thread_current;
const void *ap_hack_apr_os_thread_equal = (const void *)apr_os_thread_equal;
#endif /* APR_HAS_THREADS */
const void *ap_hack_apr_os_file_put = (const void *)apr_os_file_put;
const void *ap_hack_apr_os_pipe_put = (const void *)apr_os_pipe_put;
const void *ap_hack_apr_os_pipe_put_ex = (const void *)apr_os_pipe_put_ex;
const void *ap_hack_apr_os_dir_put = (const void *)apr_os_dir_put;
const void *ap_hack_apr_os_sock_put = (const void *)apr_os_sock_put;
const void *ap_hack_apr_os_sock_make = (const void *)apr_os_sock_make;
const void *ap_hack_apr_os_proc_mutex_put = (const void *)apr_os_proc_mutex_put;
const void *ap_hack_apr_os_imp_time_put = (const void *)apr_os_imp_time_put;
const void *ap_hack_apr_os_exp_time_put = (const void *)apr_os_exp_time_put;
const void *ap_hack_apr_os_shm_put = (const void *)apr_os_shm_put;
#if APR_HAS_DSO || defined(DOXYGEN)
const void *ap_hack_apr_os_dso_handle_put = (const void *)apr_os_dso_handle_put;
const void *ap_hack_apr_os_dso_handle_get = (const void *)apr_os_dso_handle_get;
#endif /* APR_HAS_DSO */
#if APR_HAS_OS_UUID
const void *ap_hack_apr_os_uuid_get = (const void *)apr_os_uuid_get;
#endif
const void *ap_hack_apr_os_default_encoding = (const void *)apr_os_default_encoding;
const void *ap_hack_apr_os_locale_encoding = (const void *)apr_os_locale_encoding;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_proc_mutex.h
 */
const void *ap_hack_apr_proc_mutex_create = (const void *)apr_proc_mutex_create;
const void *ap_hack_apr_proc_mutex_child_init = (const void *)apr_proc_mutex_child_init;
const void *ap_hack_apr_proc_mutex_lock = (const void *)apr_proc_mutex_lock;
const void *ap_hack_apr_proc_mutex_trylock = (const void *)apr_proc_mutex_trylock;
const void *ap_hack_apr_proc_mutex_unlock = (const void *)apr_proc_mutex_unlock;
const void *ap_hack_apr_proc_mutex_destroy = (const void *)apr_proc_mutex_destroy;
const void *ap_hack_apr_proc_mutex_cleanup = (const void *)apr_proc_mutex_cleanup;
const void *ap_hack_apr_proc_mutex_lockfile = (const void *)apr_proc_mutex_lockfile;
const void *ap_hack_apr_proc_mutex_name = (const void *)apr_proc_mutex_name;
const void *ap_hack_apr_proc_mutex_defname = (const void *)apr_proc_mutex_defname;
const void *ap_hack_apr_proc_mutex_pool_get = (const void *)apr_proc_mutex_pool_get;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_random.h
 */
const void *ap_hack_apr_crypto_sha256_new = (const void *)apr_crypto_sha256_new;
const void *ap_hack_apr_random_init = (const void *)apr_random_init;
const void *ap_hack_apr_random_standard_new = (const void *)apr_random_standard_new;
const void *ap_hack_apr_random_add_entropy = (const void *)apr_random_add_entropy;
const void *ap_hack_apr_random_insecure_bytes = (const void *)apr_random_insecure_bytes;
const void *ap_hack_apr_random_secure_bytes = (const void *)apr_random_secure_bytes;
const void *ap_hack_apr_random_barrier = (const void *)apr_random_barrier;
const void *ap_hack_apr_random_secure_ready = (const void *)apr_random_secure_ready;
const void *ap_hack_apr_random_insecure_ready = (const void *)apr_random_insecure_ready;
const void *ap_hack_apr_random_after_fork = (const void *)apr_random_after_fork;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_shm.h
 */
const void *ap_hack_apr_shm_create = (const void *)apr_shm_create;
const void *ap_hack_apr_shm_remove = (const void *)apr_shm_remove;
const void *ap_hack_apr_shm_destroy = (const void *)apr_shm_destroy;
const void *ap_hack_apr_shm_attach = (const void *)apr_shm_attach;
const void *ap_hack_apr_shm_detach = (const void *)apr_shm_detach;
const void *ap_hack_apr_shm_baseaddr_get = (const void *)apr_shm_baseaddr_get;
const void *ap_hack_apr_shm_size_get = (const void *)apr_shm_size_get;
const void *ap_hack_apr_shm_pool_get = (const void *)apr_shm_pool_get;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_signal.h
 */
#if APR_HAVE_SIGACTION || defined(DOXYGEN)
const void *ap_hack_apr_signal = (const void *)apr_signal;
#else /* !APR_HAVE_SIGACTION */
#endif
const void *ap_hack_apr_signal_description_get = (const void *)apr_signal_description_get;
const void *ap_hack_apr_signal_block = (const void *)apr_signal_block;
const void *ap_hack_apr_signal_unblock = (const void *)apr_signal_unblock;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_strings.h
 */
const void *ap_hack_apr_strnatcmp = (const void *)apr_strnatcmp;
const void *ap_hack_apr_strnatcasecmp = (const void *)apr_strnatcasecmp;
const void *ap_hack_apr_pstrdup = (const void *)apr_pstrdup;
const void *ap_hack_apr_pstrmemdup = (const void *)apr_pstrmemdup;
const void *ap_hack_apr_pstrndup = (const void *)apr_pstrndup;
const void *ap_hack_apr_pmemdup = (const void *)apr_pmemdup;
const void *ap_hack_apr_pstrcat = (const void *)apr_pstrcat;
const void *ap_hack_apr_pstrcatv = (const void *)apr_pstrcatv;
const void *ap_hack_apr_pvsprintf = (const void *)apr_pvsprintf;
const void *ap_hack_apr_psprintf = (const void *)apr_psprintf;
const void *ap_hack_apr_cpystrn = (const void *)apr_cpystrn;
const void *ap_hack_apr_collapse_spaces = (const void *)apr_collapse_spaces;
const void *ap_hack_apr_tokenize_to_argv = (const void *)apr_tokenize_to_argv;
const void *ap_hack_apr_strtok = (const void *)apr_strtok;
const void *ap_hack_apr_snprintf = (const void *)apr_snprintf;
const void *ap_hack_apr_vsnprintf = (const void *)apr_vsnprintf;
const void *ap_hack_apr_itoa = (const void *)apr_itoa;
const void *ap_hack_apr_ltoa = (const void *)apr_ltoa;
const void *ap_hack_apr_off_t_toa = (const void *)apr_off_t_toa;
const void *ap_hack_apr_strtoff = (const void *)apr_strtoff;
const void *ap_hack_apr_strtoi64 = (const void *)apr_strtoi64;
const void *ap_hack_apr_atoi64 = (const void *)apr_atoi64;
const void *ap_hack_apr_strfsize = (const void *)apr_strfsize;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_tables.h
 */
const void *ap_hack_apr_table_elts = (const void *)apr_table_elts;
const void *ap_hack_apr_is_empty_table = (const void *)apr_is_empty_table;
const void *ap_hack_apr_is_empty_array = (const void *)apr_is_empty_array;
const void *ap_hack_apr_array_make = (const void *)apr_array_make;
const void *ap_hack_apr_array_push = (const void *)apr_array_push;
const void *ap_hack_apr_array_pop = (const void *)apr_array_pop;
const void *ap_hack_apr_array_clear = (const void *)apr_array_clear;
const void *ap_hack_apr_array_cat = (const void *)apr_array_cat;
const void *ap_hack_apr_array_copy = (const void *)apr_array_copy;
const void *ap_hack_apr_array_copy_hdr = (const void *)apr_array_copy_hdr;
const void *ap_hack_apr_array_append = (const void *)apr_array_append;
const void *ap_hack_apr_array_pstrcat = (const void *)apr_array_pstrcat;
const void *ap_hack_apr_table_make = (const void *)apr_table_make;
const void *ap_hack_apr_table_copy = (const void *)apr_table_copy;
const void *ap_hack_apr_table_clone = (const void *)apr_table_clone;
const void *ap_hack_apr_table_clear = (const void *)apr_table_clear;
const void *ap_hack_apr_table_get = (const void *)apr_table_get;
const void *ap_hack_apr_table_set = (const void *)apr_table_set;
const void *ap_hack_apr_table_setn = (const void *)apr_table_setn;
const void *ap_hack_apr_table_unset = (const void *)apr_table_unset;
const void *ap_hack_apr_table_merge = (const void *)apr_table_merge;
const void *ap_hack_apr_table_mergen = (const void *)apr_table_mergen;
const void *ap_hack_apr_table_add = (const void *)apr_table_add;
const void *ap_hack_apr_table_addn = (const void *)apr_table_addn;
const void *ap_hack_apr_table_overlay = (const void *)apr_table_overlay;
const void *ap_hack_apr_table_do = (const void *)apr_table_do;
const void *ap_hack_apr_table_vdo = (const void *)apr_table_vdo;
const void *ap_hack_apr_table_overlap = (const void *)apr_table_overlap;
const void *ap_hack_apr_table_compress = (const void *)apr_table_compress;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_thread_cond.h
 */
#if APR_HAS_THREADS || defined(DOXYGEN)
const void *ap_hack_apr_thread_cond_create = (const void *)apr_thread_cond_create;
const void *ap_hack_apr_thread_cond_wait = (const void *)apr_thread_cond_wait;
const void *ap_hack_apr_thread_cond_timedwait = (const void *)apr_thread_cond_timedwait;
const void *ap_hack_apr_thread_cond_signal = (const void *)apr_thread_cond_signal;
const void *ap_hack_apr_thread_cond_broadcast = (const void *)apr_thread_cond_broadcast;
const void *ap_hack_apr_thread_cond_destroy = (const void *)apr_thread_cond_destroy;
const void *ap_hack_apr_thread_cond_pool_get = (const void *)apr_thread_cond_pool_get;
#endif /* APR_HAS_THREADS */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_thread_mutex.h
 */
#if APR_HAS_THREADS || defined(DOXYGEN)
const void *ap_hack_apr_thread_mutex_create = (const void *)apr_thread_mutex_create;
const void *ap_hack_apr_thread_mutex_lock = (const void *)apr_thread_mutex_lock;
const void *ap_hack_apr_thread_mutex_trylock = (const void *)apr_thread_mutex_trylock;
const void *ap_hack_apr_thread_mutex_unlock = (const void *)apr_thread_mutex_unlock;
const void *ap_hack_apr_thread_mutex_destroy = (const void *)apr_thread_mutex_destroy;
const void *ap_hack_apr_thread_mutex_pool_get = (const void *)apr_thread_mutex_pool_get;
#endif /* APR_HAS_THREADS */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_thread_proc.h
 */
#if APR_HAS_THREADS
const void *ap_hack_apr_threadattr_create = (const void *)apr_threadattr_create;
const void *ap_hack_apr_threadattr_detach_set = (const void *)apr_threadattr_detach_set;
const void *ap_hack_apr_threadattr_detach_get = (const void *)apr_threadattr_detach_get;
const void *ap_hack_apr_threadattr_stacksize_set = (const void *)apr_threadattr_stacksize_set;
const void *ap_hack_apr_threadattr_guardsize_set = (const void *)apr_threadattr_guardsize_set;
const void *ap_hack_apr_thread_create = (const void *)apr_thread_create;
const void *ap_hack_apr_thread_exit = (const void *)apr_thread_exit;
const void *ap_hack_apr_thread_join = (const void *)apr_thread_join;
const void *ap_hack_apr_thread_yield = (const void *)apr_thread_yield;
const void *ap_hack_apr_thread_once_init = (const void *)apr_thread_once_init;
const void *ap_hack_apr_thread_once = (const void *)apr_thread_once;
const void *ap_hack_apr_thread_detach = (const void *)apr_thread_detach;
const void *ap_hack_apr_thread_data_get = (const void *)apr_thread_data_get;
const void *ap_hack_apr_thread_data_set = (const void *)apr_thread_data_set;
const void *ap_hack_apr_threadkey_private_create = (const void *)apr_threadkey_private_create;
const void *ap_hack_apr_threadkey_private_get = (const void *)apr_threadkey_private_get;
const void *ap_hack_apr_threadkey_private_set = (const void *)apr_threadkey_private_set;
const void *ap_hack_apr_threadkey_private_delete = (const void *)apr_threadkey_private_delete;
const void *ap_hack_apr_threadkey_data_get = (const void *)apr_threadkey_data_get;
const void *ap_hack_apr_threadkey_data_set = (const void *)apr_threadkey_data_set;
#endif
const void *ap_hack_apr_procattr_create = (const void *)apr_procattr_create;
const void *ap_hack_apr_procattr_io_set = (const void *)apr_procattr_io_set;
const void *ap_hack_apr_procattr_child_in_set = (const void *)apr_procattr_child_in_set;
const void *ap_hack_apr_procattr_child_out_set = (const void *)apr_procattr_child_out_set;
const void *ap_hack_apr_procattr_child_err_set = (const void *)apr_procattr_child_err_set;
const void *ap_hack_apr_procattr_dir_set = (const void *)apr_procattr_dir_set;
const void *ap_hack_apr_procattr_cmdtype_set = (const void *)apr_procattr_cmdtype_set;
const void *ap_hack_apr_procattr_detach_set = (const void *)apr_procattr_detach_set;
#if APR_HAVE_STRUCT_RLIMIT
const void *ap_hack_apr_procattr_limit_set = (const void *)apr_procattr_limit_set;
#endif
const void *ap_hack_apr_procattr_child_errfn_set = (const void *)apr_procattr_child_errfn_set;
const void *ap_hack_apr_procattr_error_check_set = (const void *)apr_procattr_error_check_set;
const void *ap_hack_apr_procattr_addrspace_set = (const void *)apr_procattr_addrspace_set;
const void *ap_hack_apr_procattr_user_set = (const void *)apr_procattr_user_set;
const void *ap_hack_apr_procattr_group_set = (const void *)apr_procattr_group_set;
#if APR_HAS_FORK
const void *ap_hack_apr_proc_fork = (const void *)apr_proc_fork;
#endif
const void *ap_hack_apr_proc_create = (const void *)apr_proc_create;
const void *ap_hack_apr_proc_wait = (const void *)apr_proc_wait;
const void *ap_hack_apr_proc_wait_all_procs = (const void *)apr_proc_wait_all_procs;
const void *ap_hack_apr_proc_detach = (const void *)apr_proc_detach;
const void *ap_hack_apr_proc_other_child_register = (const void *)apr_proc_other_child_register;
const void *ap_hack_apr_proc_other_child_unregister = (const void *)apr_proc_other_child_unregister;
const void *ap_hack_apr_proc_other_child_alert = (const void *)apr_proc_other_child_alert;
const void *ap_hack_apr_proc_other_child_refresh = (const void *)apr_proc_other_child_refresh;
const void *ap_hack_apr_proc_other_child_refresh_all = (const void *)apr_proc_other_child_refresh_all;
const void *ap_hack_apr_proc_kill = (const void *)apr_proc_kill;
const void *ap_hack_apr_pool_note_subprocess = (const void *)apr_pool_note_subprocess;
#if APR_HAS_THREADS 
#if (APR_HAVE_SIGWAIT || APR_HAVE_SIGSUSPEND) && !defined(OS2)
const void *ap_hack_apr_setup_signal_thread = (const void *)apr_setup_signal_thread;
const void *ap_hack_apr_signal_thread = (const void *)apr_signal_thread;
#endif /* (APR_HAVE_SIGWAIT || APR_HAVE_SIGSUSPEND) && !defined(OS2) */
const void *ap_hack_apr_thread_pool_get = (const void *)apr_thread_pool_get;
#endif /* APR_HAS_THREADS */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_thread_rwlock.h
 */
#if APR_HAS_THREADS
const void *ap_hack_apr_thread_rwlock_create = (const void *)apr_thread_rwlock_create;
const void *ap_hack_apr_thread_rwlock_rdlock = (const void *)apr_thread_rwlock_rdlock;
const void *ap_hack_apr_thread_rwlock_tryrdlock = (const void *)apr_thread_rwlock_tryrdlock;
const void *ap_hack_apr_thread_rwlock_wrlock = (const void *)apr_thread_rwlock_wrlock;
const void *ap_hack_apr_thread_rwlock_trywrlock = (const void *)apr_thread_rwlock_trywrlock;
const void *ap_hack_apr_thread_rwlock_unlock = (const void *)apr_thread_rwlock_unlock;
const void *ap_hack_apr_thread_rwlock_destroy = (const void *)apr_thread_rwlock_destroy;
const void *ap_hack_apr_thread_rwlock_pool_get = (const void *)apr_thread_rwlock_pool_get;
#endif  /* APR_HAS_THREADS */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_time.h
 */
const void *ap_hack_apr_time_now = (const void *)apr_time_now;
const void *ap_hack_apr_time_ansi_put = (const void *)apr_time_ansi_put;
const void *ap_hack_apr_time_exp_tz = (const void *)apr_time_exp_tz;
const void *ap_hack_apr_time_exp_gmt = (const void *)apr_time_exp_gmt;
const void *ap_hack_apr_time_exp_lt = (const void *)apr_time_exp_lt;
const void *ap_hack_apr_time_exp_get = (const void *)apr_time_exp_get;
const void *ap_hack_apr_time_exp_gmt_get = (const void *)apr_time_exp_gmt_get;
const void *ap_hack_apr_sleep = (const void *)apr_sleep;
const void *ap_hack_apr_rfc822_date = (const void *)apr_rfc822_date;
const void *ap_hack_apr_ctime = (const void *)apr_ctime;
const void *ap_hack_apr_strftime = (const void *)apr_strftime;
const void *ap_hack_apr_time_clock_hires = (const void *)apr_time_clock_hires;

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_user.h
 */
#if APR_HAS_USER 
const void *ap_hack_apr_uid_current = (const void *)apr_uid_current;
const void *ap_hack_apr_uid_name_get = (const void *)apr_uid_name_get;
const void *ap_hack_apr_uid_get = (const void *)apr_uid_get;
const void *ap_hack_apr_uid_homepath_get = (const void *)apr_uid_homepath_get;
#if defined(WIN32)
const void *ap_hack_apr_uid_compare = (const void *)apr_uid_compare;
#else
#endif
const void *ap_hack_apr_gid_name_get = (const void *)apr_gid_name_get;
const void *ap_hack_apr_gid_get = (const void *)apr_gid_get;
#if defined(WIN32)
const void *ap_hack_apr_gid_compare = (const void *)apr_gid_compare;
#else
#endif
#endif  /* ! APR_HAS_USER */

/*
 * /home/utcpdev/mtcp/apps/apache_benchmark/srclib/apr/include/apr_version.h
 */
#ifndef APR_VERSION_ONLY
const void *ap_hack_apr_version = (const void *)apr_version;
const void *ap_hack_apr_version_string = (const void *)apr_version_string;
#endif /* ndef APR_VERSION_ONLY */

