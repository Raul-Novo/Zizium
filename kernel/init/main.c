// SPDX-License-Identifier: GPL-3.0-or-later

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "zi/arch_x64.h"
#include "zi/block.h"
#include "zi/boot.h"
#include "zi/byte_order.h"
#include "zi/display.h"
#include "zi/early_shell.h"
#include "zi/framebuffer_console.h"
#include "zi/kernel_memory.h"
#include "zi/kernel_pool.h"
#include "zi/log.h"
#include "zi/memory.h"
#include "zi/memory_stress.h"
#include "zi/path.h"
#include "zi/phase4_acceptance.h"
#include "zi/pool.h"
#include "zi/process_parameters.h"
#include "zi/security.h"
#include "zi/serial.h"
#include "zi/service.h"
#include "zi/storage_bootstrap.h"
#include "zi/system_bootstrap.h"
#include "zi/user_image.h"
#include "zi/user_process.h"
#include "zi/x64_interrupt.h"
#include "zi/zifs.h"
#include "zi/zifs_image_source.h"
#include "zi/zifs_journal.h"
#include "zi/zifs_recovery.h"
#include "zi/zifs_security.h"
#include "zi/zifs_transaction.h"
#include "zizium/status.h"
#include "zizium/types.h"

typedef struct ZiBootModuleBlockContext {
  const unsigned char* data;
  size_t size;
} ZiBootModuleBlockContext;

typedef struct ZiKernelMainContinuation {
  const ZiBootContext* boot_context;
  uint64_t guard_fault_address;
} ZiKernelMainContinuation;

typedef struct ZiUserAcceptanceProgramme {
  ZiStringView file_path;
  ZiStringView module_name;
  const ZiProcessParameterInput* parameters;
  int32_t expected_exit_code;
  const char* success_marker;
} ZiUserAcceptanceProgramme;

typedef struct ZiFaultInjectedBlockContext {
  const ZiBlockDevice* parent;
  uint64_t operation_count;
  uint64_t fail_operation;
} ZiFaultInjectedBlockContext;

typedef enum ZiFsBootTestMode {
  ZIFS_BOOT_TEST_MODE_NONE = 0,
  ZIFS_BOOT_TEST_MODE_CREATE = 1,
  ZIFS_BOOT_TEST_MODE_CRASH_ROLLBACK = 2,
  ZIFS_BOOT_TEST_MODE_CRASH_REPLAY = 3,
  ZIFS_BOOT_TEST_MODE_VERIFY_PRESENT = 4,
  ZIFS_BOOT_TEST_MODE_VERIFY_ABSENT = 5,
  ZIFS_BOOT_TEST_MODE_WRAP_CREATE = 6,
  ZIFS_BOOT_TEST_MODE_WRAP_VERIFY = 7,
  ZIFS_BOOT_TEST_MODE_RENAME_MOVE = 8,
  ZIFS_BOOT_TEST_MODE_RENAME_MOVE_VERIFY = 9,
  ZIFS_BOOT_TEST_MODE_MOVE_CRASH_ROLLBACK = 10,
  ZIFS_BOOT_TEST_MODE_MOVE_CRASH_REPLAY = 11,
  ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_OLD = 12,
  ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_NEW = 13,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE = 14,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE_VERIFY = 15,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK = 16,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_REPLAY = 17,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_OLD = 18,
  ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_NEW = 19,
  ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK = 20,
  ZIFS_BOOT_TEST_MODE_DELETE_CRASH_REPLAY = 21,
  ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_OLD = 22,
  ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_NEW = 23,
} ZiFsBootTestMode;

typedef struct ZiFsBootTestSelection {
  const char* token;
  ZiFsBootTestMode mode;
} ZiFsBootTestSelection;

#define CORE_SERVICE_MANIFEST_COUNT 5u
#define USER_IMAGE_SOURCE_FILE_LIMIT ((size_t)64u * (size_t)1024u)
#define USER_IMAGE_SOURCE_TOTAL_LIMIT ((size_t)128u * (size_t)1024u)
#define ZIFS_TEST_ROLLBACK_FAIL_OPERATION UINT64_C(12)
#define ZIFS_TEST_REPLAY_FAIL_OPERATION UINT64_C(16)

static const ZiStringView k_user_environment[] = {
    {"SystemRoot=C:\\Zizium", sizeof "SystemRoot=C:\\Zizium" - 1u},
    {"ReleaseChannel=Preview", sizeof "ReleaseChannel=Preview" - 1u},
};
static const ZiStringView k_standard_arguments[] = {
    {"C:\\Zizium\\System\\hello_standard.exe",
     sizeof "C:\\Zizium\\System\\hello_standard.exe" - 1u},
};
static const ZiStringView k_argument_arguments[] = {
    {"C:\\Zizium\\System\\hello_arguments.exe",
     sizeof "C:\\Zizium\\System\\hello_arguments.exe" - 1u},
    {"C:\\Program Files\\Zizium Seed", sizeof "C:\\Program Files\\Zizium Seed" - 1u},
    {"azul claro", sizeof "azul claro" - 1u},
};
static const ZiStringView k_native_arguments[] = {
    {"C:\\Zizium\\System\\hello_native.exe", sizeof "C:\\Zizium\\System\\hello_native.exe" - 1u},
};
static const ZiProcessParameterInput k_standard_parameters = {
    sizeof(ZiProcessParameterInput),
    ZI_PROCESS_PARAMETER_INPUT_VERSION,
    {"C:\\Zizium\\System\\hello_standard.exe",
     sizeof "C:\\Zizium\\System\\hello_standard.exe" - 1u},
    {"C:\\Zizium\\System\\hello_standard.exe",
     sizeof "C:\\Zizium\\System\\hello_standard.exe" - 1u},
    k_standard_arguments,
    sizeof k_standard_arguments / sizeof k_standard_arguments[0],
    k_user_environment,
    sizeof k_user_environment / sizeof k_user_environment[0],
};
static const ZiProcessParameterInput k_argument_parameters = {
    sizeof(ZiProcessParameterInput),
    ZI_PROCESS_PARAMETER_INPUT_VERSION,
    {"C:\\Zizium\\System\\hello_arguments.exe",
     sizeof "C:\\Zizium\\System\\hello_arguments.exe" - 1u},
    {"\"C:\\Zizium\\System\\hello_arguments.exe\" \"C:\\Program Files\\Zizium Seed\" "
     "\"azul claro\"",
     sizeof "\"C:\\Zizium\\System\\hello_arguments.exe\" \"C:\\Program Files\\Zizium "
            "Seed\" \"azul claro\"" -
         1u},
    k_argument_arguments,
    sizeof k_argument_arguments / sizeof k_argument_arguments[0],
    k_user_environment,
    sizeof k_user_environment / sizeof k_user_environment[0],
};
static const ZiProcessParameterInput k_native_parameters = {
    sizeof(ZiProcessParameterInput),
    ZI_PROCESS_PARAMETER_INPUT_VERSION,
    {"C:\\Zizium\\System\\hello_native.exe", sizeof "C:\\Zizium\\System\\hello_native.exe" - 1u},
    {"C:\\Zizium\\System\\hello_native.exe", sizeof "C:\\Zizium\\System\\hello_native.exe" - 1u},
    k_native_arguments,
    sizeof k_native_arguments / sizeof k_native_arguments[0],
    k_user_environment,
    sizeof k_user_environment / sizeof k_user_environment[0],
};
static const ZiUserAcceptanceProgramme k_user_programmes[] = {
    {{"C:\\Zizium\\System\\hello_standard.exe",
      sizeof "C:\\Zizium\\System\\hello_standard.exe" - 1u},
     {"hello_standard.exe", sizeof "hello_standard.exe" - 1u},
     &k_standard_parameters,
     21,
     "STANDARD_C_MAIN"},
    {{"C:\\Zizium\\System\\hello_arguments.exe",
      sizeof "C:\\Zizium\\System\\hello_arguments.exe" - 1u},
     {"hello_arguments.exe", sizeof "hello_arguments.exe" - 1u},
     &k_argument_parameters,
     22,
     "STANDARD_C_ARGUMENTS"},
    {{"C:\\Zizium\\System\\hello_native.exe", sizeof "C:\\Zizium\\System\\hello_native.exe" - 1u},
     {"hello_native.exe", sizeof "hello_native.exe" - 1u},
     &k_native_parameters,
     23,
     "ZIA_LIBRARY"},
};
static const ZiFsImageSourceRequest k_core_library_requests[] = {
    {{"zx.dll", sizeof "zx.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zx.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zx.dll" - 1u}},
    {{"zicrt.dll", sizeof "zicrt.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zicrt.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zicrt.dll" - 1u}},
    {{"zia.dll", sizeof "zia.dll" - 1u},
     {"C:\\Zizium\\System21\\Libraries\\zia.dll",
      sizeof "C:\\Zizium\\System21\\Libraries\\zia.dll" - 1u}},
};
static const ZiFsBootTestSelection k_zifs_boot_test_selections[] = {
    {"zi.test=zifs-create", ZIFS_BOOT_TEST_MODE_CREATE},
    {"zi.test=zifs-crash-rollback", ZIFS_BOOT_TEST_MODE_CRASH_ROLLBACK},
    {"zi.test=zifs-crash-replay", ZIFS_BOOT_TEST_MODE_CRASH_REPLAY},
    {"zi.test=zifs-verify-present", ZIFS_BOOT_TEST_MODE_VERIFY_PRESENT},
    {"zi.test=zifs-verify-absent", ZIFS_BOOT_TEST_MODE_VERIFY_ABSENT},
    {"zi.test=zifs-wrap-create", ZIFS_BOOT_TEST_MODE_WRAP_CREATE},
    {"zi.test=zifs-wrap-verify", ZIFS_BOOT_TEST_MODE_WRAP_VERIFY},
    {"zi.test=zifs-rename-move", ZIFS_BOOT_TEST_MODE_RENAME_MOVE},
    {"zi.test=zifs-rename-move-verify", ZIFS_BOOT_TEST_MODE_RENAME_MOVE_VERIFY},
    {"zi.test=zifs-move-crash-rollback", ZIFS_BOOT_TEST_MODE_MOVE_CRASH_ROLLBACK},
    {"zi.test=zifs-move-crash-replay", ZIFS_BOOT_TEST_MODE_MOVE_CRASH_REPLAY},
    {"zi.test=zifs-move-verify-old", ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_OLD},
    {"zi.test=zifs-move-verify-new", ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_NEW},
    {"zi.test=zifs-truncate-delete", ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE},
    {"zi.test=zifs-truncate-delete-verify", ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE_VERIFY},
    {"zi.test=zifs-truncate-crash-rollback", ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK},
    {"zi.test=zifs-truncate-crash-replay", ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_REPLAY},
    {"zi.test=zifs-truncate-verify-old", ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_OLD},
    {"zi.test=zifs-truncate-verify-new", ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_NEW},
    {"zi.test=zifs-delete-crash-rollback", ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK},
    {"zi.test=zifs-delete-crash-replay", ZIFS_BOOT_TEST_MODE_DELETE_CRASH_REPLAY},
    {"zi.test=zifs-delete-verify-old", ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_OLD},
    {"zi.test=zifs-delete-verify-new", ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_NEW},
};

static ZiFsVolume g_root_volume;
static unsigned char g_zifs_block_buffer[ZI_FS_BLOCK_SIZE];
static ZiBootModuleBlockContext g_module_block_context;
static ZiKernelMainContinuation g_main_continuation;
static ZiStorageBootstrap g_storage_bootstrap;
static ZiFaultInjectedBlockContext g_zifs_fault_context;
static ZiBlockDevice g_zifs_fault_device;
static unsigned char g_zifs_transaction_workspace[ZI_FS_TRANSACTION_WORKSPACE_SIZE];
static unsigned char g_zifs_recovery_workspace[ZI_FS_RECOVERY_WORKSPACE_SIZE];
static unsigned char g_zifs_test_payload[5000];
static unsigned char g_zifs_test_readback[sizeof g_zifs_test_payload];
static unsigned char g_zifs_wrap_payload[ZI_FS_TRANSACTION_MAXIMUM_DATA_BLOCKS * ZI_FS_BLOCK_SIZE];
static ZiUserProcessManager g_user_process_manager;
static ZiSystemBootstrap g_system_bootstrap;
static char g_service_manifest_data[CORE_SERVICE_MANIFEST_COUNT][ZI_SERVICE_MAX_MANIFEST_BYTES] = {
    0};
static ZiServiceDependency g_service_dependencies[CORE_SERVICE_MANIFEST_COUNT]
                                                 [ZI_SERVICE_MAX_DEPENDENCIES] = {0};
static ZiServiceManifest g_service_manifests[CORE_SERVICE_MANIFEST_COUNT] = {0};
static size_t g_service_start_order[CORE_SERVICE_MANIFEST_COUNT] = {0};
static size_t g_service_start_order_count;

static ZiStatus boot_module_read(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size);
static const ZiBootModule* find_zifs_module(const ZiBootContext* context);
static ZiStatus initialise_root_storage(const ZiBootContext* context);
static ZiStatus initialise_direct_root_storage(const ZiBootContext* context, uint32_t flags);
static ZiStatus contain_expected_storage_failure(ZiStatus status,
                                                 bool force_timeout,
                                                 bool expect_corrupt_gpt,
                                                 bool expect_corrupt_security);
static ZiStatus mount_root_block_device(const ZiBlockDevice* device);
static ZiStatus mount_root_module(const ZiBootContext* context);
static ZiStatus initialise_fault_block_device(const ZiBlockDevice* parent,
                                              uint64_t fail_operation,
                                              ZiBlockDevice** out_device);
static ZiStatus fault_block_read(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size);
static ZiStatus fault_block_write(void* context,
                                  uint64_t first_block,
                                  uint32_t block_count,
                                  const void* input,
                                  size_t input_size);
static ZiStatus fault_block_flush(void* context);
static uint64_t zifs_test_fault_operation(const char* command_line);
static ZiStatus select_zifs_boot_test_mode(const char* command_line, ZiFsBootTestMode* out_mode);
static ZiStatus consider_zifs_boot_test_mode(const char* command_line,
                                             const char* token,
                                             ZiFsBootTestMode candidate,
                                             ZiFsBootTestMode* mode);
static ZiStatus failure_status_or(ZiStatus status, ZiStatus fallback);
static ZiStatus run_requested_zifs_test(const ZiBootContext* context);
static ZiStatus verify_zifs_test_file(bool expected_present);
static ZiStatus run_zifs_wrap_create(void);
static ZiStatus run_zifs_wrap_verify(void);
static ZiStatus run_zifs_rename_move(void);
static ZiStatus run_zifs_crash_move(ZiFsBootTestMode mode);
static ZiStatus verify_zifs_rename_move(bool expected_complete);
static ZiStatus verify_zifs_crash_move(bool expected_complete);
static ZiStatus run_zifs_truncate_delete(void);
static ZiStatus verify_zifs_truncate_delete(void);
static ZiStatus run_zifs_crash_truncate(ZiFsBootTestMode mode);
static ZiStatus verify_zifs_crash_truncate(bool expected_complete);
static ZiStatus run_zifs_crash_delete(ZiFsBootTestMode mode);
static ZiStatus verify_zifs_crash_delete(bool expected_complete);
static ZiStatus prepare_and_commit_zifs_move(const char* source_parent_path,
                                             size_t source_parent_path_size,
                                             ZiStringView source_name,
                                             const char* target_parent_path,
                                             size_t target_parent_path_size,
                                             ZiStringView target_name,
                                             uint32_t expected_image_count,
                                             uint64_t fail_operation);
static ZiStatus prepare_and_commit_zifs_truncate(const char* file_path,
                                                 size_t file_path_size,
                                                 uint64_t new_size,
                                                 uint64_t failure_offset,
                                                 ZiFsTruncateResult* out_result);
static ZiStatus prepare_and_commit_zifs_delete(const char* parent_path,
                                               size_t parent_path_size,
                                               ZiStringView name,
                                               uint64_t failure_offset,
                                               ZiFsDeleteResult* out_result);
static ZiStatus prepare_and_commit_zifs_create(const char* parent_path,
                                               size_t parent_path_size,
                                               ZiStringView name,
                                               ZiConstBuffer data,
                                               ZiFsCreateResult* out_result);
static ZiStatus
verify_zifs_truncated_pe(const char* file_path, size_t file_path_size, uint64_t expected_size);
static ZiStatus
read_zifs_u64_file(const char* file_path, size_t file_path_size, uint64_t* out_value);
static ZiStatus prepare_zifs_reuse_probe(uint64_t forbidden_or_expected_block, bool expect_reuse);
static ZiStatus lookup_zifs_record(const char* path_text,
                                   size_t path_size,
                                   ZiFsFileRecord* out_record,
                                   uint64_t* out_record_index);
static ZiStatus verify_zifs_pe_path(const char* file_path,
                                    size_t file_path_size,
                                    const char* parent_path,
                                    size_t parent_path_size,
                                    bool expected_present);
static ZiStatus verify_zifs_named_file(const char* file_path,
                                       size_t file_path_size,
                                       ZiConstBuffer expected_data,
                                       bool expected_present);
static void log_storage_progress(uint32_t completed_flags);
static ZiStatus run_user_process_acceptance(bool force_user_fault);
static ZiStatus release_user_processes(ZiUserProcess* const* processes, size_t process_count);
static ZiStatus image_source_allocate(void* context, size_t size, void** out_allocation);
static ZiStatus image_source_release(void* context, void* allocation);
static _Noreturn void kernel_main_on_guarded_stack(void* context);
static _Noreturn void run_architecture_fault_test(const char* test_name);
static _Noreturn void run_memory_guard_fault_test(uint64_t guard_fault_address);
static void run_requested_architecture_test(const ZiBootContext* context,
                                            uint64_t guard_fault_address);
static ZiStatus verify_case_sensitive_lookup(void);
static ZiStatus verify_zifs_security(void);
static ZiStatus verify_zifs_file_read(void);
static ZiStatus verify_service_manifests(void);
static bool command_line_has_token(const char* command_line, const char* token);
static const char* memory_status_message(ZiStatus status);
static const char* virtual_memory_stage_message(uint32_t stage);
static size_t text_size(const char* text);
static bool text_equal(const char* left, const char* right);
static bool text_ends_with(const char* text, const char* ending);

// Assembly calls this externally visible kernel entry after establishing the C ABI.
// NOLINTNEXTLINE(misc-use-internal-linkage)
_Noreturn void ZkKernelMain(void) {
  if (ZiFailed(zi_serial_initialise())) {
    ZkArchHalt();
  }
  zi_log_initialise();
  zi_log_boot_marker("ENTRY");
  zi_log_boot_marker("SERIAL");
  zi_log_write(ZI_LOG_INFORMATION, "Boot", "COM1 serial logging is active at 115200 baud.");

  ZiStatus status = zi_x64_cpu_initialise();
  if (ZiFailed(status)) {
    zi_panic("The kernel could not establish its x64 descriptor and interrupt tables.");
  }
  zi_log_boot_marker("CPU_TABLES");
  zi_log_boot_marker("EXCEPTION_READY");
  zi_log_write(ZI_LOG_INFORMATION,
               "Architecture",
               "Kernel-owned GDT, TSS, IST, and IDT state is active.");

  const ZiBootContext* boot_context = NULL;
  zi_log_boot_marker("BOOT_CONTEXT_BEGIN");
  status = zi_boot_context_from_limine(&boot_context);
  if (ZiFailed(status) || boot_context == NULL) {
    zi_panic("Limine did not provide a valid revision-6 boot context.");
  }
  zi_log_boot_marker("BOOT_CONTEXT");
  zi_log_write(ZI_LOG_INFORMATION, "Boot", "The Limine response was translated to ZiBootContext.");

  status = zi_kernel_memory_initialise(boot_context);
  if (ZiFailed(status)) {
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The physical memory inventory or page allocator could not be established.");
  }
  zi_log_boot_marker("MEMORY_INVENTORY");
  zi_log_boot_marker("PMM_READY");
  zi_log_write(ZI_LOG_INFORMATION,
               "Memory",
               "The validated physical memory inventory and ownership allocator are active.");

  status = zi_kernel_virtual_memory_initialise(boot_context);
  if (ZiFailed(status)) {
    zi_log_write(ZI_LOG_ERROR,
                 "Memory",
                 virtual_memory_stage_message(zi_kernel_virtual_memory_stage()));
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The kernel could not install its owned x64 page tables.");
  }
  zi_log_boot_marker("VMM_READY");
  zi_log_write(ZI_LOG_INFORMATION,
               "Memory",
               "Kernel-owned four-level page tables enforce NX and writable-or-executable pages.");
  status = zi_kernel_temporary_mapping_self_test();
  if (ZiFailed(status)) {
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The temporary physical-page mapping did not preserve data or ownership.");
  }
  zi_log_boot_marker("TEMPORARY_MAPPING");

  status = zi_kernel_pool_initialise();
  if (ZiSucceeded(status)) {
    status = zi_kernel_pool_self_test();
  }
  if (ZiFailed(status)) {
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The corruption-checked kernel pool or object cache failed validation.");
  }
  zi_log_boot_marker("HEAP_READY");
  zi_log_write(ZI_LOG_INFORMATION,
               "Memory",
               "The corruption-checked kernel pool and descriptor cache are active.");

  uintptr_t guarded_stack_top = 0;
  uint64_t guard_fault_address = 0;
  status = zi_x64_guarded_stacks_initialise(&guarded_stack_top, &guard_fault_address);
  if (ZiFailed(status) || guarded_stack_top == 0 || guard_fault_address == 0) {
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The kernel could not install guarded bootstrap and exception stacks.");
  }
  zi_log_boot_marker("GUARDED_STACKS");
  g_main_continuation.boot_context = boot_context;
  g_main_continuation.guard_fault_address = guard_fault_address;
  ZkArchSwitchStackAndCall(guarded_stack_top, kernel_main_on_guarded_stack, &g_main_continuation);
}

// Bootstrap ordering is kept linear so every fatal boundary has an unambiguous boot marker.
// NOLINTNEXTLINE(readability-function-size)
static _Noreturn void kernel_main_on_guarded_stack(void* context) {
  if (context == NULL) {
    zi_panic("The guarded-stack continuation context is absent.");
  }
  const ZiKernelMainContinuation* continuation = context;
  const ZiBootContext* boot_context = continuation->boot_context;
  if (boot_context == NULL) {
    zi_panic("The guarded-stack continuation lost its boot context.");
  }
  run_requested_architecture_test(boot_context, continuation->guard_fault_address);

  ZiStatus status = zi_kernel_memory_stress_test();
  if (ZiFailed(status)) {
    zi_log_write(ZI_LOG_ERROR, "Memory", memory_status_message(status));
    zi_panic("The PMM, VMM, pool, cache, or guarded-stack stress test failed.");
  }
  zi_log_boot_marker("MEMORY_STRESS");
  zi_log_write(ZI_LOG_INFORMATION,
               "Memory",
               "Repeated allocation, mapping, cache, and guarded-stack stress is leak-neutral.");

  bool framebuffer_ready = false;
  for (size_t index = 0; index < boot_context->display_output_count; ++index) {
    ZiDisplayOutput* output = &boot_context->display_outputs[index];
    status = zi_framebuffer_console_initialise(&output->framebuffer, output->scale);
    if (ZiSucceeded(status)) {
      framebuffer_ready = true;
      break;
    }
  }
  if (framebuffer_ready) {
    zi_log_set_sink(zi_framebuffer_console_write);
    zi_log_boot_marker("FRAMEBUFFER");
    zi_log_write(ZI_LOG_INFORMATION, "Display", "The calm early framebuffer terminal is active.");
  } else {
    zi_log_boot_marker("FRAMEBUFFER_FALLBACK");
    zi_log_write(ZI_LOG_WARNING,
                 "Display",
                 "No supported XRGB framebuffer was supplied; continuing through serial.");
  }

  status = initialise_root_storage(boot_context);
  if (ZiFailed(status)) {
    zi_log_write_hex(ZI_LOG_ERROR, "Storage", "Storage initialisation status", (uint32_t)status);
    zi_log_write_hex(ZI_LOG_ERROR,
                     "Storage",
                     "Storage initialisation stage",
                     g_storage_bootstrap.stage);
    zi_panic("The native storage path could not mount the ZiFS root volume.");
  }
  zi_log_boot_marker("ZIFS_MOUNT");
  zi_log_write(ZI_LOG_INFORMATION,
               "ZiFS",
               "Mounted the genuine ZiFS root volume with its validated device policy.");

  status = verify_zifs_security();
  if (ZiFailed(status)) {
    zi_panic("ZiFS durable security-descriptor verification failed.");
  }
  zi_log_boot_marker("ZIFS_SECURITY");
  zi_log_write(ZI_LOG_INFORMATION,
               "Security",
               "Loaded the root ACL from ZiFS and verified allow, deny, and default-deny policy.");

  status = run_requested_zifs_test(boot_context);
  if (ZiFailed(status)) {
    zi_log_write_hex(ZI_LOG_ERROR, "ZiFS", "Writable transaction test status", (uint32_t)status);
    zi_panic("The requested ZiFS writable transaction test failed.");
  }

  status = verify_case_sensitive_lookup();
  if (ZiFailed(status)) {
    zi_panic("ZiFS exact-case lookup verification failed.");
  }
  zi_log_boot_marker("CASE_SENSITIVE");
  zi_log_write(ZI_LOG_INFORMATION,
               "ZiFS",
               "Verified that C:\\Temp exists while C:\\temp does not.");

  status = verify_zifs_file_read();
  if (ZiFailed(status)) {
    zi_panic("ZiFS regular-file read verification failed.");
  }
  zi_log_boot_marker("ZIFS_FILE_READ");
  zi_log_write(ZI_LOG_INFORMATION,
               "ZiFS",
               "Read a PE image header from C:\\Zizium\\System through ZiFS extents.");

  status = verify_service_manifests();
  if (ZiFailed(status)) {
    zi_panic("The core service manifests or their dependency graph are invalid.");
  }
  zi_log_boot_marker("SERVICE_MANIFESTS");
  zi_log_boot_marker("SERVICE_DEPENDENCIES");
  zi_log_write(ZI_LOG_INFORMATION,
               "Service",
               "Parsed core .zsvc files from ZiFS and resolved their exact-case dependency DAG.");

  bool force_user_fault = command_line_has_token(boot_context->command_line, "zi.test=user-fault");
  status = run_user_process_acceptance(force_user_fault);
  if (ZiFailed(status)) {
    zi_log_write_hex(ZI_LOG_ERROR, "Process", "User-process acceptance status", (uint32_t)status);
    zi_panic("The Phase 3 user-process acceptance sequence failed.");
  }
  if (force_user_fault) {
    zi_log_write(ZI_LOG_INFORMATION,
                 "Process",
                 "The deliberate Ring-3 fault was contained and its address space was reclaimed.");
  } else {
    zi_log_write(ZI_LOG_INFORMATION,
                 "Process",
                 "Three isolated PE processes completed relocation, imports, parameters, and "
                 "waitable exit.");
  }

  status = zi_x64_preemption_start(zi_kernel_apic_virtual_address());
  if (ZiFailed(status)) {
    zi_panic("Local-APIC timer bring-up or kernel pre-emption verification failed.");
  }

  status = zi_system_bootstrap_initialise(&g_system_bootstrap,
                                          &g_root_volume,
                                          g_zifs_block_buffer,
                                          sizeof g_zifs_block_buffer,
                                          &g_user_process_manager);
  if (ZiSucceeded(status)) {
    status = zi_system_bootstrap_run(&g_system_bootstrap,
                                     g_service_manifests,
                                     CORE_SERVICE_MANIFEST_COUNT,
                                     g_service_start_order,
                                     g_service_start_order_count);
  }
  if (ZiFailed(status)) {
    zi_log_write_hex(ZI_LOG_ERROR, "Session", "System bootstrap status", (uint32_t)status);
    zi_panic("The filesystem-backed service and user session bootstrap failed.");
  }

  bool recovery_shell =
      (bool)(command_line_has_token(boot_context->command_line, "zi.shell=recovery") ||
             command_line_has_token(boot_context->command_line, "zi.storage=module") ||
             command_line_has_token(boot_context->command_line, "zi.test=storage-timeout") ||
             command_line_has_token(boot_context->command_line, "zi.test=storage-corrupt-gpt"));
  if (recovery_shell) {
    ZiEarlyShellContext shell_context = {boot_context, &g_root_volume};
    zi_log_boot_marker("LUMA_READY");
    zi_log_write(ZI_LOG_INFORMATION,
                 "Luma",
                 "The explicit early recovery shell is ready on the serial console.");
    zi_early_luma_run(&shell_context);
  }
  zi_log_write(ZI_LOG_INFORMATION,
               "Session",
               "The filesystem-backed user-mode Luma acceptance session completed cleanly.");
  ZkArchHalt();
}

static _Noreturn void run_architecture_fault_test(const char* test_name) {
  if (text_equal(test_name, "exception-ud")) {
    zi_log_boot_marker("FAULT_TEST_INVALID_OPCODE");
    ZkArchTriggerInvalidOpcode();
  }
  zi_log_boot_marker("FAULT_TEST_PAGE_FAULT");
  ZkArchTriggerPageFault();
}

static _Noreturn void run_memory_guard_fault_test(uint64_t guard_fault_address) {
  zi_log_boot_marker("FAULT_TEST_MEMORY_GUARD");
  *(volatile uint8_t*)(uintptr_t)guard_fault_address = UINT8_C(0x5a);
  zi_panic("A mapped kernel stack guard failed to raise a page fault.");
}

static void run_requested_architecture_test(const ZiBootContext* context,
                                            uint64_t guard_fault_address) {
  if (context == NULL || context->command_line == NULL) {
    return;
  }
  if (command_line_has_token(context->command_line, "zi.test=exception-ud")) {
    run_architecture_fault_test("exception-ud");
  }
  if (command_line_has_token(context->command_line, "zi.test=exception-pf")) {
    run_architecture_fault_test("exception-pf");
  }
  if (command_line_has_token(context->command_line, "zi.test=memory-guard")) {
    run_memory_guard_fault_test(guard_fault_address);
  }
}

static ZiStatus boot_module_read(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size) {
  if (context == NULL || output == NULL || first_block > SIZE_MAX / ZI_FS_BLOCK_SIZE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiBootModuleBlockContext* module = context;
  size_t offset = (size_t)first_block * ZI_FS_BLOCK_SIZE;
  size_t byte_count = (size_t)block_count * ZI_FS_BLOCK_SIZE;
  if (offset > module->size || byte_count > module->size - offset || output_size < byte_count) {
    return ZI_STATUS_OUT_OF_BOUNDS;
  }
  zi_memory_copy(output, module->data + offset, byte_count);
  return ZI_STATUS_SUCCESS;
}

static const ZiBootModule* find_zifs_module(const ZiBootContext* context) {
  for (size_t index = 0; index < context->module_count; ++index) {
    const ZiBootModule* module = &context->modules[index];
    if ((module->command_line != NULL && text_equal(module->command_line, "zifs-root")) ||
        (module->path != NULL && text_ends_with(module->path, ".zifs"))) {
      return module;
    }
  }
  return NULL;
}

// The bounded sequence is deliberately synchronous until scheduler-owned Ring-3 threads exist.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus run_user_process_acceptance(bool force_user_fault) {
  ZiPoolStatistics pool_before = {0};
  ZiStatus status = zi_kernel_pool_statistics(&pool_before);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsImageSourceAllocator source_allocator = {
      sizeof(ZiFsImageSourceAllocator),
      ZI_FS_IMAGE_SOURCE_ALLOCATOR_VERSION,
      NULL,
      USER_IMAGE_SOURCE_FILE_LIMIT,
      USER_IMAGE_SOURCE_TOTAL_LIMIT,
      image_source_allocate,
      image_source_release,
  };
  ZiFsImageSourceSet libraries = {0};
  status = zi_zifs_image_source_set_load(&g_root_volume,
                                         k_core_library_requests,
                                         sizeof k_core_library_requests /
                                             sizeof k_core_library_requests[0],
                                         &source_allocator,
                                         g_zifs_block_buffer,
                                         sizeof g_zifs_block_buffer,
                                         &libraries);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiSecurityId groups[] = {{ZI_SECURITY_AUTHORITY_GROUP, 1}};
  ZiAccessToken tokens[sizeof k_user_programmes / sizeof k_user_programmes[0]] = {0};
  for (size_t index = 0; index < sizeof tokens / sizeof tokens[0]; ++index) {
    tokens[index] = (ZiAccessToken){
        sizeof(ZiAccessToken),
        ZI_ACCESS_TOKEN_VERSION,
        {ZI_SECURITY_AUTHORITY_USER, (uint32_t)index + 1u},
        groups,
        sizeof groups / sizeof groups[0],
        0,
    };
  }
  status = zi_user_process_manager_initialise(&g_user_process_manager);
  if (ZiFailed(status)) {
    ZiStatus release_status = zi_zifs_image_source_set_release(&source_allocator, &libraries);
    if (ZiFailed(release_status)) {
      return ZI_STATUS_MEMORY_CORRUPTION;
    }
    return status;
  }

  ZiPhysicalMemoryStatistics before = zi_kernel_memory_statistics();
  ZiUserProcess* processes[sizeof k_user_programmes / sizeof k_user_programmes[0]] = {0};
  size_t process_count = sizeof processes / sizeof processes[0];
  if (force_user_fault) {
    process_count = 1;
  }
  for (size_t index = 0; index < process_count; ++index) {
    const ZiUserAcceptanceProgramme* definition = &k_user_programmes[index];
    ZiFsImageSourceRequest request = {definition->module_name, definition->file_path};
    ZiFsImageSourceSet main_source = {0};
    status = zi_zifs_image_source_set_load(&g_root_volume,
                                           &request,
                                           1,
                                           &source_allocator,
                                           g_zifs_block_buffer,
                                           sizeof g_zifs_block_buffer,
                                           &main_source);
    if (ZiSucceeded(status)) {
      ZiUserProcessLaunch launch = {
          sizeof(ZiUserProcessLaunch),
          ZI_USER_PROCESS_LAUNCH_VERSION,
          definition->module_name,
          main_source.sources[0].file_data,
          main_source.sources[0].file_size,
          libraries.sources,
          libraries.source_count,
          definition->parameters,
          &tokens[index],
          ZI_USER_IMAGE_LOAD_FORCE_RELOCATION,
          0,
      };
      status = zi_user_process_create(&g_user_process_manager, &launch, &processes[index]);
    }
    if (main_source.version != 0) {
      ZiStatus release_status = zi_zifs_image_source_set_release(&source_allocator, &main_source);
      if (ZiSucceeded(status) && ZiFailed(release_status)) {
        status = ZI_STATUS_MEMORY_CORRUPTION;
      }
    }
    if (ZiFailed(status)) {
      break;
    }
  }
  ZiStatus library_release_status = zi_zifs_image_source_set_release(&source_allocator, &libraries);
  if (ZiSucceeded(status) && ZiFailed(library_release_status)) {
    status = ZI_STATUS_MEMORY_CORRUPTION;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("FILESYSTEM_PE_SOURCE");
    zi_log_boot_marker("USER_PROCESS_SET");
  }

  ZiPhase4AcceptanceResult phase4_result = {0};
  bool phase4_cleanup_is_armed = false;
  if (ZiSucceeded(status) && !force_user_fault && process_count >= 2) {
    status = zi_phase4_acceptance_run(processes[0],
                                      processes[1],
                                      &g_user_process_manager.dispatcher_domain,
                                      &phase4_result);
    if ((phase4_result.completed_mask & ZI_PHASE4_ACCEPTANCE_OBJECT_NAMESPACE) != 0) {
      zi_log_boot_marker("OBJECT_NAMESPACE");
    }
    if ((phase4_result.completed_mask & ZI_PHASE4_ACCEPTANCE_HANDLE_ACCESS) != 0) {
      zi_log_boot_marker("HANDLE_ACCESS");
    }
    if ((phase4_result.completed_mask & ZI_PHASE4_ACCEPTANCE_WAIT_OBJECTS) != 0) {
      zi_log_boot_marker("WAIT_OBJECTS");
    }
    if ((phase4_result.completed_mask & ZI_PHASE4_ACCEPTANCE_IPC_EXCHANGE) != 0) {
      zi_log_boot_marker("IPC_EXCHANGE");
    }
    if ((phase4_result.completed_mask & ZI_PHASE4_ACCEPTANCE_HANDLE_TRANSFER) != 0) {
      zi_log_boot_marker("IPC_HANDLE_TRANSFER");
    }
    phase4_cleanup_is_armed = ZiSucceeded(status);
  }

  for (size_t index = 0; ZiSucceeded(status) && index < process_count; ++index) {
    ZiStatus run_status =
        zi_user_process_run(&g_user_process_manager, processes[index], force_user_fault);
    int32_t exit_code = 0;
    ZiStatus wait_status = zi_user_process_wait(processes[index], 0, &exit_code);
    if (force_user_fault) {
      if (run_status != ZI_STATUS_PROCESS_TERMINATED || ZiFailed(wait_status) ||
          exit_code != ZI_STATUS_PROCESS_TERMINATED) {
        status = ZI_STATUS_INVALID_STATE;
      }
      continue;
    }
    if (ZiFailed(run_status) || ZiFailed(wait_status) ||
        exit_code != k_user_programmes[index].expected_exit_code) {
      if (ZiFailed(run_status)) {
        status = run_status;
      } else {
        status = ZI_STATUS_INVALID_STATE;
      }
      continue;
    }
    zi_log_boot_marker(k_user_programmes[index].success_marker);
  }

  ZiStatus release_status = release_user_processes(processes, process_count);
  ZiStatus phase4_cleanup_status = ZI_STATUS_SUCCESS;
  if (phase4_cleanup_is_armed) {
    phase4_cleanup_status = zi_phase4_acceptance_verify_process_cleanup();
    if (ZiSucceeded(phase4_cleanup_status)) {
      zi_log_boot_marker("IPC_PROCESS_CLEAN");
    }
  }
  ZiPhysicalMemoryStatistics after = zi_kernel_memory_statistics();
  ZiPoolStatistics pool_after = {0};
  ZiStatus pool_status = zi_kernel_pool_statistics(&pool_after);
  if (ZiSucceeded(status) && ZiFailed(release_status)) {
    status = release_status;
  }
  if (ZiSucceeded(status) && ZiFailed(phase4_cleanup_status)) {
    status = phase4_cleanup_status;
  }
  if (ZiSucceeded(status) && ZiFailed(pool_status)) {
    status = pool_status;
  }
  if (ZiSucceeded(status) &&
      (g_user_process_manager.process_count != 0 || before.free_pages != after.free_pages ||
       before.allocated_pages != after.allocated_pages ||
       pool_before.allocation_count != pool_after.allocation_count ||
       pool_before.allocated_bytes != pool_after.allocated_bytes)) {
    status = ZI_STATUS_MEMORY_CORRUPTION;
  }
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("USER_PROCESS_SET_CLEAN");
  }
  return status;
}

static ZiStatus image_source_allocate(void* context, size_t size, void** out_allocation) {
  (void)context;
  return zi_kernel_pool_allocate(size, out_allocation);
}

static ZiStatus image_source_release(void* context, void* allocation) {
  (void)context;
  return zi_kernel_pool_free(allocation);
}

static ZiStatus release_user_processes(ZiUserProcess* const* processes, size_t process_count) {
  if (processes == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus result = ZI_STATUS_SUCCESS;
  while (process_count != 0) {
    ZiUserProcess* process = processes[--process_count];
    if (process == NULL) {
      continue;
    }
    ZiStatus status = zi_user_process_release(&g_user_process_manager, process);
    if (ZiSucceeded(result) && ZiFailed(status)) {
      result = status;
    }
  }
  return result;
}

static ZiStatus initialise_root_storage(const ZiBootContext* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  bool module_requested = command_line_has_token(context->command_line, "zi.storage=module");
  bool force_timeout = command_line_has_token(context->command_line, "zi.test=storage-timeout");
  bool expect_corrupt_gpt =
      command_line_has_token(context->command_line, "zi.test=storage-corrupt-gpt");
  bool expect_corrupt_security =
      command_line_has_token(context->command_line, "zi.test=zifs-security-corrupt");
  if (!module_requested) {
    uint32_t flags = ZI_STORAGE_INITIALISE_NONE;
    if (force_timeout) {
      flags = ZI_STORAGE_INITIALISE_FORCE_NVME_TIMEOUT;
    }
    ZiStatus status = initialise_direct_root_storage(context, flags);
    if (ZiSucceeded(status)) {
      return status;
    }
    status = contain_expected_storage_failure(status,
                                              force_timeout,
                                              expect_corrupt_gpt,
                                              expect_corrupt_security);
    if (ZiFailed(status)) {
      return status;
    }
  }

  zi_log_boot_marker("STORAGE_MODULE_FALLBACK");
  zi_log_write(ZI_LOG_WARNING,
               "Storage",
               "Using the explicitly requested Limine ZiFS recovery module.");
  return mount_root_module(context);
}

static ZiStatus initialise_direct_root_storage(const ZiBootContext* context, uint32_t flags) {
  const ZiBlockDevice* partition = NULL;
  ZiStatus status =
      zi_storage_bootstrap_initialise(context, flags, &g_storage_bootstrap, &partition);
  log_storage_progress(g_storage_bootstrap.completed_flags);
  if (ZiFailed(status)) {
    return status;
  }
  const ZiBlockDevice* root_device = partition;
  uint64_t fail_operation = zifs_test_fault_operation(context->command_line);
  if (fail_operation != 0) {
    ZiBlockDevice* fault_device = NULL;
    status = initialise_fault_block_device(partition, fail_operation, &fault_device);
    if (ZiFailed(status)) {
      return status;
    }
    root_device = fault_device;
  }
  status = mount_root_block_device(root_device);
  if (ZiFailed(status)) {
    return status;
  }
  zi_log_boot_marker("ZIFS_DIRECT");
  zi_log_write(ZI_LOG_INFORMATION,
               "Storage",
               "Mounted ZiFS through the NVMe and GPT partition path.");
  return ZI_STATUS_SUCCESS;
}

static ZiStatus contain_expected_storage_failure(ZiStatus status,
                                                 bool force_timeout,
                                                 bool expect_corrupt_gpt,
                                                 bool expect_corrupt_security) {
  if (force_timeout) {
    if (status == ZI_STATUS_TIMEOUT && g_storage_bootstrap.stage == ZI_STORAGE_STAGE_NVME) {
      zi_log_boot_marker("STORAGE_TIMEOUT_SAFE");
      zi_log_write(ZI_LOG_WARNING,
                   "Storage",
                   "The injected NVMe timeout was contained without leaking active state.");
      return ZI_STATUS_SUCCESS;
    }
  }
  if (expect_corrupt_gpt) {
    if (g_storage_bootstrap.stage == ZI_STORAGE_STAGE_GPT) {
      zi_log_boot_marker("GPT_CORRUPTION_SAFE");
      zi_log_write(ZI_LOG_WARNING,
                   "Storage",
                   "The injected GPT corruption was rejected before ZiFS mounting.");
      return ZI_STATUS_SUCCESS;
    }
  }
  if (expect_corrupt_security && g_storage_bootstrap.stage == ZI_STORAGE_STAGE_READY &&
      (status == ZI_STATUS_CHECKSUM_MISMATCH || status == ZI_STATUS_CORRUPT_FILESYSTEM)) {
    zi_log_boot_marker("ZIFS_SECURITY_CORRUPTION_SAFE");
    zi_log_write(ZI_LOG_WARNING,
                 "Security",
                 "The corrupted ZiFS security table was rejected before root-volume use.");
    return ZI_STATUS_SUCCESS;
  }
  return status;
}

static ZiStatus mount_root_block_device(const ZiBlockDevice* device) {
  if (device == NULL || device->struct_size < sizeof *device ||
      device->version != ZI_BLOCK_DEVICE_VERSION) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status =
      ZiFsMountVolume(device, g_zifs_block_buffer, sizeof g_zifs_block_buffer, &g_root_volume);
  if (status != ZI_STATUS_RECOVERY_REQUIRED) {
    return status;
  }
  if ((device->flags & (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) !=
      (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) {
    return status;
  }

  ZiFsRecoveryReport report = {0};
  status = ZiFsRecoverVolume(&g_root_volume,
                             g_zifs_recovery_workspace,
                             sizeof g_zifs_recovery_workspace,
                             &report);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsVolume remounted = {0};
  status = ZiFsMountVolume(device, g_zifs_block_buffer, sizeof g_zifs_block_buffer, &remounted);
  if (ZiFailed(status)) {
    return status;
  }
  g_root_volume = remounted;
  if (report.action == ZI_FS_RECOVERY_ACTION_REPAIRED_REDUNDANCY) {
    zi_log_boot_marker("ZIFS_RECOVERY_REPAIR");
  } else if (report.action == ZI_FS_RECOVERY_ACTION_ROLLED_BACK) {
    zi_log_boot_marker("ZIFS_RECOVERY_ROLLBACK");
  } else if (report.action == ZI_FS_RECOVERY_ACTION_REPLAYED) {
    zi_log_boot_marker("ZIFS_RECOVERY_REPLAY");
  } else {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus initialise_fault_block_device(const ZiBlockDevice* parent,
                                              uint64_t fail_operation,
                                              ZiBlockDevice** out_device) {
  if (parent == NULL || out_device == NULL || fail_operation == 0 ||
      parent->struct_size < sizeof *parent || parent->version != ZI_BLOCK_DEVICE_VERSION ||
      parent->read_blocks == NULL || parent->write_blocks == NULL || parent->flush == NULL ||
      (parent->flags & (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) !=
          (ZI_BLOCK_DEVICE_WRITE_SUPPORTED | ZI_BLOCK_DEVICE_FLUSH_SUPPORTED)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  g_zifs_fault_context.parent = parent;
  g_zifs_fault_context.operation_count = 0;
  g_zifs_fault_context.fail_operation = fail_operation;
  g_zifs_fault_device = (ZiBlockDevice){
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &g_zifs_fault_context,
      parent->block_size,
      parent->block_count,
      fault_block_read,
      fault_block_flush,
      parent->flags,
      fault_block_write,
  };
  *out_device = &g_zifs_fault_device;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus fault_block_read(void* context,
                                 uint64_t first_block,
                                 uint32_t block_count,
                                 void* output,
                                 size_t output_size) {
  ZiFaultInjectedBlockContext* fault = context;
  if (fault == NULL || fault->parent == NULL || fault->parent->read_blocks == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  return fault->parent->read_blocks(fault->parent->context,
                                    first_block,
                                    block_count,
                                    output,
                                    output_size);
}

static ZiStatus fault_block_write(void* context,
                                  uint64_t first_block,
                                  uint32_t block_count,
                                  const void* input,
                                  size_t input_size) {
  ZiFaultInjectedBlockContext* fault = context;
  if (fault == NULL || fault->parent == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ++fault->operation_count;
  if (fault->operation_count == fault->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return zi_block_write(fault->parent, first_block, block_count, input, input_size);
}

static ZiStatus fault_block_flush(void* context) {
  ZiFaultInjectedBlockContext* fault = context;
  if (fault == NULL || fault->parent == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ++fault->operation_count;
  if (fault->operation_count == fault->fail_operation) {
    return ZI_STATUS_DEVICE_ERROR;
  }
  return zi_block_barrier(fault->parent);
}

static uint64_t zifs_test_fault_operation(const char* command_line) {
  if (command_line_has_token(command_line, "zi.test=zifs-move-crash-rollback") ||
      command_line_has_token(command_line, "zi.test=zifs-move-crash-replay") ||
      command_line_has_token(command_line, "zi.test=zifs-truncate-crash-rollback") ||
      command_line_has_token(command_line, "zi.test=zifs-truncate-crash-replay") ||
      command_line_has_token(command_line, "zi.test=zifs-delete-crash-rollback") ||
      command_line_has_token(command_line, "zi.test=zifs-delete-crash-replay")) {
    return UINT64_MAX;
  }
  if (command_line_has_token(command_line, "zi.test=zifs-crash-rollback")) {
    return ZIFS_TEST_ROLLBACK_FAIL_OPERATION;
  }
  if (command_line_has_token(command_line, "zi.test=zifs-crash-replay")) {
    return ZIFS_TEST_REPLAY_FAIL_OPERATION;
  }
  return 0;
}

static ZiStatus select_zifs_boot_test_mode(const char* command_line, ZiFsBootTestMode* out_mode) {
  if (out_mode == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *out_mode = ZIFS_BOOT_TEST_MODE_NONE;
  for (size_t index = 0;
       index < sizeof k_zifs_boot_test_selections / sizeof k_zifs_boot_test_selections[0];
       ++index) {
    ZiStatus status = consider_zifs_boot_test_mode(command_line,
                                                   k_zifs_boot_test_selections[index].token,
                                                   k_zifs_boot_test_selections[index].mode,
                                                   out_mode);
    if (ZiFailed(status)) {
      return status;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus consider_zifs_boot_test_mode(const char* command_line,
                                             const char* token,
                                             ZiFsBootTestMode candidate,
                                             ZiFsBootTestMode* mode) {
  if (!command_line_has_token(command_line, token)) {
    return ZI_STATUS_SUCCESS;
  }
  if (*mode != ZIFS_BOOT_TEST_MODE_NONE) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  *mode = candidate;
  return ZI_STATUS_SUCCESS;
}

static ZiStatus failure_status_or(ZiStatus status, ZiStatus fallback) {
  if (ZiFailed(status)) {
    return status;
  }
  return fallback;
}

// Dedicated QEMU modes halt after their durable marker so the harness can cut power.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus run_requested_zifs_test(const ZiBootContext* context) {
  if (context == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsBootTestMode mode = ZIFS_BOOT_TEST_MODE_NONE;
  ZiStatus status = select_zifs_boot_test_mode(context->command_line, &mode);
  if (ZiFailed(status)) {
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_NONE) {
    return ZI_STATUS_SUCCESS;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE) {
    status = run_zifs_truncate_delete();
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_RECLAIM_AFTER_CHECKPOINT");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_DELETE_VERIFY) {
    status = verify_zifs_truncate_delete();
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_TRUNCATE_DELETE_PERSISTED");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK ||
      mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_REPLAY) {
    status = run_zifs_crash_truncate(mode);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker(mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK
                             ? "ZIFS_TRUNCATE_CRASH_ROLLBACK_BOUNDARY"
                             : "ZIFS_TRUNCATE_CRASH_REPLAY_BOUNDARY");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_OLD ||
      mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_NEW) {
    bool expected_complete = mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_VERIFY_NEW;
    status = verify_zifs_crash_truncate(expected_complete);
    if (ZiSucceeded(status)) {
      if (expected_complete) {
        zi_log_boot_marker("ZIFS_TRUNCATE_NEW_STATE");
      } else {
        zi_log_boot_marker("ZIFS_TRUNCATE_OLD_STATE");
      }
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK ||
      mode == ZIFS_BOOT_TEST_MODE_DELETE_CRASH_REPLAY) {
    status = run_zifs_crash_delete(mode);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker(mode == ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK
                             ? "ZIFS_DELETE_CRASH_ROLLBACK_BOUNDARY"
                             : "ZIFS_DELETE_CRASH_REPLAY_BOUNDARY");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_OLD ||
      mode == ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_NEW) {
    bool expected_complete = mode == ZIFS_BOOT_TEST_MODE_DELETE_VERIFY_NEW;
    status = verify_zifs_crash_delete(expected_complete);
    if (ZiSucceeded(status)) {
      if (expected_complete) {
        zi_log_boot_marker("ZIFS_DELETE_NEW_STATE");
      } else {
        zi_log_boot_marker("ZIFS_DELETE_OLD_STATE");
      }
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_RENAME_MOVE) {
    status = run_zifs_rename_move();
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_RENAME_MOVE_COMMIT");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_RENAME_MOVE_VERIFY) {
    status = verify_zifs_rename_move(true);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_RENAME_MOVE_PERSISTED");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_MOVE_CRASH_ROLLBACK ||
      mode == ZIFS_BOOT_TEST_MODE_MOVE_CRASH_REPLAY) {
    status = run_zifs_crash_move(mode);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker(mode == ZIFS_BOOT_TEST_MODE_MOVE_CRASH_ROLLBACK
                             ? "ZIFS_MOVE_CRASH_ROLLBACK_BOUNDARY"
                             : "ZIFS_MOVE_CRASH_REPLAY_BOUNDARY");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_OLD || mode == ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_NEW) {
    bool expected_complete = mode == ZIFS_BOOT_TEST_MODE_MOVE_VERIFY_NEW;
    status = verify_zifs_crash_move(expected_complete);
    if (ZiSucceeded(status)) {
      if (expected_complete) {
        zi_log_boot_marker("ZIFS_MOVE_PERSISTED");
      } else {
        zi_log_boot_marker("ZIFS_MOVE_OLD_STATE");
      }
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_WRAP_CREATE) {
    status = run_zifs_wrap_create();
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_JOURNAL_WRAPPED");
      ZkArchHalt();
    }
    return status;
  }
  if (mode == ZIFS_BOOT_TEST_MODE_WRAP_VERIFY) {
    status = run_zifs_wrap_verify();
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_WRAP_PERSISTED");
      ZkArchHalt();
    }
    return status;
  }
  for (size_t index = 0; index < sizeof g_zifs_test_payload; ++index) {
    g_zifs_test_payload[index] = (unsigned char)(index ^ (index >> 8u));
  }

  if (mode == ZIFS_BOOT_TEST_MODE_VERIFY_PRESENT || mode == ZIFS_BOOT_TEST_MODE_VERIFY_ABSENT) {
    bool expected_present = false;
    if (mode == ZIFS_BOOT_TEST_MODE_VERIFY_PRESENT) {
      expected_present = true;
    }
    status = verify_zifs_test_file(expected_present);
    if (ZiFailed(status)) {
      return status;
    }
    if (expected_present) {
      zi_log_boot_marker("ZIFS_WRITE_PERSISTED");
    } else {
      zi_log_boot_marker("ZIFS_WRITE_ABSENT");
    }
    ZkArchHalt();
  }

  status = verify_zifs_test_file(false);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsFileRecord root = {0};
  status = ZiFsReadFileRecord(&g_root_volume,
                              g_root_volume.superblock.root_record_index,
                              g_zifs_block_buffer,
                              sizeof g_zifs_block_buffer,
                              &root);
  if (ZiFailed(status) || root.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  ZiFsCreateResult result = {0};
  ZiFsCreateRequest request = {0};
  request.struct_size = sizeof request;
  request.version = ZI_FS_CREATE_REQUEST_VERSION;
  request.parent_record_index = g_root_volume.superblock.root_record_index;
  request.security_id = root.security_id;
  request.timestamp = UINT64_C(21000000);
  request.name = (ZiStringView){"Phase7 Durable.txt", sizeof "Phase7 Durable.txt" - 1u};
  request.data = (ZiConstBuffer){g_zifs_test_payload, sizeof g_zifs_test_payload};
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareCreateFile(&transaction, &request, &result);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (transaction.block_image_count != 5 || result.data_block_count != 2) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (mode == ZIFS_BOOT_TEST_MODE_CRASH_ROLLBACK || mode == ZIFS_BOOT_TEST_MODE_CRASH_REPLAY) {
    uint64_t expected_operation = ZIFS_TEST_REPLAY_FAIL_OPERATION;
    if (mode == ZIFS_BOOT_TEST_MODE_CRASH_ROLLBACK) {
      expected_operation = ZIFS_TEST_ROLLBACK_FAIL_OPERATION;
    }
    if (status != ZI_STATUS_DEVICE_ERROR ||
        g_zifs_fault_context.operation_count != expected_operation ||
        transaction.state != ZI_FS_TRANSACTION_STATE_FAILED) {
      return ZI_STATUS_INVALID_STATE;
    }
    if (mode == ZIFS_BOOT_TEST_MODE_CRASH_ROLLBACK) {
      zi_log_boot_marker("ZIFS_CRASH_ROLLBACK_BOUNDARY");
    } else {
      zi_log_boot_marker("ZIFS_CRASH_REPLAY_BOUNDARY");
    }
    ZkArchHalt();
  }
  if (ZiFailed(status)) {
    return status;
  }
  status = verify_zifs_test_file(true);
  if (ZiFailed(status)) {
    return status;
  }
  zi_log_boot_marker("ZIFS_WRITE_COMMIT");
  ZkArchHalt();
}

static ZiStatus verify_zifs_test_file(bool expected_present) {
  const char file_path[] = "C:\\Phase7 Durable.txt";
  return verify_zifs_named_file(file_path,
                                sizeof file_path - 1u,
                                (ZiConstBuffer){g_zifs_test_payload, sizeof g_zifs_test_payload},
                                expected_present);
}

// The two commits intentionally consume 30 then five records in a 32-record ring.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus run_zifs_wrap_create(void) {
  for (size_t index = 0; index < sizeof g_zifs_wrap_payload; ++index) {
    g_zifs_wrap_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0x5a));
  }
  const char large_path[] = "C:\\Wide Journal.bin";
  const char wrapped_path[] = "C:\\Wrapped.txt";
  const ZiConstBuffer large_data = {g_zifs_wrap_payload, sizeof g_zifs_wrap_payload};
  const ZiConstBuffer empty_data = {NULL, 0};
  ZiStatus status = verify_zifs_named_file(large_path, sizeof large_path - 1u, large_data, false);
  if (ZiSucceeded(status)) {
    status = verify_zifs_named_file(wrapped_path, sizeof wrapped_path - 1u, empty_data, false);
  }

  ZiFsFileRecord root = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsReadFileRecord(&g_root_volume,
                                g_root_volume.superblock.root_record_index,
                                g_zifs_block_buffer,
                                sizeof g_zifs_block_buffer,
                                &root);
  }
  if (ZiFailed(status) || root.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiFsTransaction transaction = {0};
  ZiFsCreateResult result = {0};
  ZiFsCreateRequest request = {
      sizeof(ZiFsCreateRequest),
      ZI_FS_CREATE_REQUEST_VERSION,
      g_root_volume.superblock.root_record_index,
      root.security_id,
      UINT64_C(21000000),
      {"Wide Journal.bin", sizeof "Wide Journal.bin" - 1u},
      large_data,
  };
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareCreateFile(&transaction, &request, &result);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (transaction.block_image_capacity != ZI_FS_TRANSACTION_MAXIMUM_BLOCK_IMAGES ||
      transaction.block_image_count != 27 || result.data_block_count != 24) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (ZiFailed(status)) {
    return status;
  }

  zi_memory_zero(&transaction, sizeof transaction);
  zi_memory_zero(&result, sizeof result);
  request.name = (ZiStringView){"Wrapped.txt", sizeof "Wrapped.txt" - 1u};
  request.data = empty_data;
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareCreateFile(&transaction, &request, &result);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (transaction.block_image_count != 2 || result.data_block_count != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (ZiFailed(status)) {
    return status;
  }

  ZiFsJournalHeader journal = {0};
  uint32_t journal_copy = 0;
  status = ZiFsLoadJournalHeader(&g_root_volume.device,
                                 g_root_volume.superblock.journal_start,
                                 g_zifs_block_buffer,
                                 sizeof g_zifs_block_buffer,
                                 &journal,
                                 &journal_copy);
  uint64_t occupied_records = 0;
  uint64_t available_records = 0;
  if (ZiFailed(status) || journal.head_record != 3 || journal.tail_record != 3 ||
      journal.next_sequence != 36 || journal.last_committed_transaction != 2 ||
      journal.last_checkpoint_transaction != 2 ||
      ZiFailed(ZiFsJournalQuerySpace(&journal, &occupied_records, &available_records)) ||
      occupied_records != 0 || available_records != 31) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  status = verify_zifs_named_file(large_path, sizeof large_path - 1u, large_data, true);
  if (ZiSucceeded(status)) {
    status = verify_zifs_named_file(wrapped_path, sizeof wrapped_path - 1u, empty_data, true);
  }
  return status;
}

static ZiStatus run_zifs_wrap_verify(void) {
  for (size_t index = 0; index < sizeof g_zifs_wrap_payload; ++index) {
    g_zifs_wrap_payload[index] = (unsigned char)(index ^ (index >> 8u) ^ UINT8_C(0x5a));
  }
  const char large_path[] = "C:\\Wide Journal.bin";
  const char wrapped_path[] = "C:\\Wrapped.txt";
  ZiStatus status =
      verify_zifs_named_file(large_path,
                             sizeof large_path - 1u,
                             (ZiConstBuffer){g_zifs_wrap_payload, sizeof g_zifs_wrap_payload},
                             true);
  if (ZiSucceeded(status)) {
    status = verify_zifs_named_file(wrapped_path,
                                    sizeof wrapped_path - 1u,
                                    (ZiConstBuffer){NULL, 0},
                                    true);
  }
  ZiFsJournalHeader journal = {0};
  uint32_t journal_copy = 0;
  if (ZiSucceeded(status)) {
    status = ZiFsLoadJournalHeader(&g_root_volume.device,
                                   g_root_volume.superblock.journal_start,
                                   g_zifs_block_buffer,
                                   sizeof g_zifs_block_buffer,
                                   &journal,
                                   &journal_copy);
  }
  if (ZiFailed(status) || journal.head_record != 3 || journal.tail_record != 3 ||
      journal.next_sequence != 36 || journal.last_committed_transaction != 2 ||
      journal.last_checkpoint_transaction != 2) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus run_zifs_rename_move(void) {
  const char source_parent[] = "C:\\Program Files\\Zizium";
  const char target_parent[] = "C:\\Temp";
  const ZiStringView original_name = {"Hello Seed.exe", sizeof "Hello Seed.exe" - 1u};
  const ZiStringView renamed_name = {"hello seed.exe", sizeof "hello seed.exe" - 1u};
  const ZiStringView moved_name = {"First Light Seed.exe", sizeof "First Light Seed.exe" - 1u};
  ZiStatus status = verify_zifs_rename_move(false);
  if (ZiSucceeded(status)) {
    status = prepare_and_commit_zifs_move(source_parent,
                                          sizeof source_parent - 1u,
                                          original_name,
                                          source_parent,
                                          sizeof source_parent - 1u,
                                          renamed_name,
                                          2,
                                          0);
  }
  if (ZiSucceeded(status)) {
    status = prepare_and_commit_zifs_move(source_parent,
                                          sizeof source_parent - 1u,
                                          renamed_name,
                                          target_parent,
                                          sizeof target_parent - 1u,
                                          moved_name,
                                          3,
                                          0);
  }
  if (ZiSucceeded(status)) {
    status = verify_zifs_rename_move(true);
  }
  return status;
}

static ZiStatus run_zifs_crash_move(ZiFsBootTestMode mode) {
  if (mode != ZIFS_BOOT_TEST_MODE_MOVE_CRASH_ROLLBACK &&
      mode != ZIFS_BOOT_TEST_MODE_MOVE_CRASH_REPLAY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStatus status = verify_zifs_crash_move(false);
  if (ZiFailed(status)) {
    return status;
  }
  const char source_parent[] = "C:\\Program Files\\Zizium";
  const char target_parent[] = "C:\\Temp";
  uint64_t fail_operation = 3u + 7u;
  if (mode == ZIFS_BOOT_TEST_MODE_MOVE_CRASH_REPLAY) {
    fail_operation = 3u + 11u;
  }
  return prepare_and_commit_zifs_move(
      source_parent,
      sizeof source_parent - 1u,
      (ZiStringView){"Hello Seed.exe", sizeof "Hello Seed.exe" - 1u},
      target_parent,
      sizeof target_parent - 1u,
      (ZiStringView){"Crash Moved Seed.exe", sizeof "Crash Moved Seed.exe" - 1u},
      3,
      fail_operation);
}

static ZiStatus verify_zifs_rename_move(bool expected_complete) {
  const char source_parent[] = "C:\\Program Files\\Zizium";
  const char target_parent[] = "C:\\Temp";
  const char original_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char renamed_path[] = "C:\\Program Files\\Zizium\\hello seed.exe";
  const char moved_path[] = "C:\\Temp\\First Light Seed.exe";
  bool expected_original = true;
  if (expected_complete) {
    expected_original = false;
  }
  ZiStatus status = verify_zifs_pe_path(original_path,
                                        sizeof original_path - 1u,
                                        source_parent,
                                        sizeof source_parent - 1u,
                                        expected_original);
  if (ZiSucceeded(status)) {
    status = verify_zifs_pe_path(renamed_path,
                                 sizeof renamed_path - 1u,
                                 source_parent,
                                 sizeof source_parent - 1u,
                                 false);
  }
  if (ZiSucceeded(status)) {
    status = verify_zifs_pe_path(moved_path,
                                 sizeof moved_path - 1u,
                                 target_parent,
                                 sizeof target_parent - 1u,
                                 expected_complete);
  }
  return status;
}

static ZiStatus verify_zifs_crash_move(bool expected_complete) {
  const char source_parent[] = "C:\\Program Files\\Zizium";
  const char target_parent[] = "C:\\Temp";
  const char original_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char moved_path[] = "C:\\Temp\\Crash Moved Seed.exe";
  bool expected_original = true;
  if (expected_complete) {
    expected_original = false;
  }
  ZiStatus status = verify_zifs_pe_path(original_path,
                                        sizeof original_path - 1u,
                                        source_parent,
                                        sizeof source_parent - 1u,
                                        expected_original);
  if (ZiSucceeded(status)) {
    status = verify_zifs_pe_path(moved_path,
                                 sizeof moved_path - 1u,
                                 target_parent,
                                 sizeof target_parent - 1u,
                                 expected_complete);
  }
  return status;
}

// The clean path persists both mutations, then proves the lowest released block is reusable.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus run_zifs_truncate_delete(void) {
  const char truncate_path[] = "C:\\Temp\\Truncate Seed.bin";
  const char delete_parent[] = "C:\\Program Files\\Zizium";
  const char delete_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char reclaim_path[] = "C:\\Temp\\Reclaimed After Checkpoint.bin";
  const char reclaim_parent[] = "C:\\Temp";
  const ZiStringView delete_name = {"Hello Seed.exe", sizeof "Hello Seed.exe" - 1u};
  const ZiStringView reclaim_name = {"Reclaimed After Checkpoint.bin",
                                     sizeof "Reclaimed After Checkpoint.bin" - 1u};
  const unsigned char reclaim_byte = UINT8_C(0x21);

  ZiFsFileRecord truncate_record = {0};
  ZiFsFileRecord delete_record = {0};
  uint64_t truncate_record_index = 0;
  uint64_t delete_record_index = 0;
  ZiStatus status = lookup_zifs_record(truncate_path,
                                       sizeof truncate_path - 1u,
                                       &truncate_record,
                                       &truncate_record_index);
  if (ZiSucceeded(status)) {
    status = lookup_zifs_record(delete_path,
                                sizeof delete_path - 1u,
                                &delete_record,
                                &delete_record_index);
  }
  ZiFsFileRecord unexpected = {0};
  uint64_t unexpected_index = 0;
  if (ZiSucceeded(status)) {
    ZiStatus absent =
        lookup_zifs_record(reclaim_path, sizeof reclaim_path - 1u, &unexpected, &unexpected_index);
    status = absent == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_ALREADY_EXISTS;
  }
  if (ZiFailed(status) || truncate_record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      truncate_record.extent_count != 1 || truncate_record.extents[0].block_count < 3 ||
      truncate_record.file_size <= UINT64_C(4097) ||
      delete_record.file_type != ZI_FS_FILE_TYPE_REGULAR || delete_record.extent_count == 0) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  uint64_t first_truncate_release = truncate_record.extents[0].physical_block + 2u;
  uint64_t first_delete_release = delete_record.extents[0].physical_block;
  uint64_t expected_reuse =
      first_truncate_release < first_delete_release ? first_truncate_release : first_delete_release;

  ZiFsTruncateResult truncate_result = {0};
  status = prepare_and_commit_zifs_truncate(truncate_path,
                                            sizeof truncate_path - 1u,
                                            UINT64_C(4097),
                                            0,
                                            &truncate_result);
  if (ZiSucceeded(status)) {
    zi_log_boot_marker("ZIFS_TRUNCATE_COMMIT");
  }
  if (ZiSucceeded(status) && (truncate_result.record_index != truncate_record_index ||
                              truncate_result.released_block_count == 0)) {
    status = ZI_STATUS_INVALID_STATE;
  }
  ZiFsDeleteResult delete_result = {0};
  if (ZiSucceeded(status)) {
    status = prepare_and_commit_zifs_delete(delete_parent,
                                            sizeof delete_parent - 1u,
                                            delete_name,
                                            0,
                                            &delete_result);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_DELETE_COMMIT");
    }
  }
  if (ZiSucceeded(status) && (delete_result.record_index != delete_record_index ||
                              delete_result.released_block_count == 0)) {
    status = ZI_STATUS_INVALID_STATE;
  }
  ZiFsCreateResult create_result = {0};
  if (ZiSucceeded(status)) {
    status = prepare_and_commit_zifs_create(reclaim_parent,
                                            sizeof reclaim_parent - 1u,
                                            reclaim_name,
                                            (ZiConstBuffer){&reclaim_byte, 1},
                                            &create_result);
    if (ZiSucceeded(status)) {
      zi_log_boot_marker("ZIFS_RECLAIM_COMMIT");
    }
  }
  if (ZiSucceeded(status) &&
      (create_result.data_block_count != 1 || create_result.first_data_block != expected_reuse)) {
    status = ZI_STATUS_INVALID_STATE;
  }
  if (ZiSucceeded(status)) {
    status = verify_zifs_truncate_delete();
  }
  return status;
}

static ZiStatus verify_zifs_truncate_delete(void) {
  const char truncate_path[] = "C:\\Temp\\Truncate Seed.bin";
  const char delete_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char reclaim_path[] = "C:\\Temp\\Reclaimed After Checkpoint.bin";
  ZiStatus status =
      verify_zifs_truncated_pe(truncate_path, sizeof truncate_path - 1u, UINT64_C(4097));
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  if (ZiSucceeded(status)) {
    ZiStatus deleted =
        lookup_zifs_record(delete_path, sizeof delete_path - 1u, &record, &record_index);
    status = deleted == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (ZiSucceeded(status)) {
    status = lookup_zifs_record(reclaim_path, sizeof reclaim_path - 1u, &record, &record_index);
  }
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.file_size != 1 ||
      record.extent_count == 0) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        g_zifs_test_readback,
                        1,
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  return ZiSucceeded(status) && bytes_read == 1 && g_zifs_test_readback[0] == UINT8_C(0x21)
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus run_zifs_crash_truncate(ZiFsBootTestMode mode) {
  if (mode != ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK &&
      mode != ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_REPLAY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const char file_path[] = "C:\\Temp\\Truncate Seed.bin";
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, sizeof file_path - 1u, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.extent_count != 1 ||
      record.extents[0].block_count < 3 || record.file_size <= UINT64_C(4097)) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  uint64_t failure_offset = mode == ZIFS_BOOT_TEST_MODE_TRUNCATE_CRASH_ROLLBACK ? 7u : 11u;
  ZiFsTruncateResult result = {0};
  status = prepare_and_commit_zifs_truncate(file_path,
                                            sizeof file_path - 1u,
                                            UINT64_C(4097),
                                            failure_offset,
                                            &result);
  if (ZiFailed(status)) {
    return status;
  }
  if (result.record_index != record_index || result.released_block_count == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_zifs_crash_truncate(bool expected_complete) {
  const char file_path[] = "C:\\Temp\\Truncate Seed.bin";
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, sizeof file_path - 1u, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.extent_count != 1 ||
      record.extents[0].block_count < 2) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  if ((expected_complete && record.file_size != UINT64_C(4097)) ||
      (!expected_complete && record.file_size <= UINT64_C(4097))) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        g_zifs_test_readback,
                        2,
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  if (ZiFailed(status) || bytes_read != 2 || g_zifs_test_readback[0] != 'M' ||
      g_zifs_test_readback[1] != 'Z') {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  uint64_t first_release = record.extents[0].physical_block + 2u;
  return prepare_zifs_reuse_probe(first_release, expected_complete);
}

static ZiStatus run_zifs_crash_delete(ZiFsBootTestMode mode) {
  if (mode != ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK &&
      mode != ZIFS_BOOT_TEST_MODE_DELETE_CRASH_REPLAY) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  const char parent_path[] = "C:\\Program Files\\Zizium";
  const char file_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char anchor_path[] = "C:\\Temp";
  const ZiStringView file_name = {"Hello Seed.exe", sizeof "Hello Seed.exe" - 1u};
  const ZiStringView anchor_name = {"Delete Reclaim Anchor.bin",
                                    sizeof "Delete Reclaim Anchor.bin" - 1u};
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, sizeof file_path - 1u, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.extent_count == 0) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  unsigned char encoded_block[sizeof(uint64_t)] = {0};
  zi_write_u64_le(encoded_block, record.extents[0].physical_block);
  ZiFsCreateResult anchor_result = {0};
  status = prepare_and_commit_zifs_create(anchor_path,
                                          sizeof anchor_path - 1u,
                                          anchor_name,
                                          (ZiConstBuffer){encoded_block, sizeof encoded_block},
                                          &anchor_result);
  if (ZiFailed(status) || anchor_result.data_block_count != 1) {
    return failure_status_or(status, ZI_STATUS_INVALID_STATE);
  }
  uint64_t failure_offset = mode == ZIFS_BOOT_TEST_MODE_DELETE_CRASH_ROLLBACK ? 7u : 11u;
  ZiFsDeleteResult result = {0};
  status = prepare_and_commit_zifs_delete(parent_path,
                                          sizeof parent_path - 1u,
                                          file_name,
                                          failure_offset,
                                          &result);
  if (ZiFailed(status)) {
    return status;
  }
  if (result.record_index != record_index || result.released_block_count == 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_zifs_crash_delete(bool expected_complete) {
  const char file_path[] = "C:\\Program Files\\Zizium\\Hello Seed.exe";
  const char anchor_path[] = "C:\\Temp\\Delete Reclaim Anchor.bin";
  uint64_t first_release = 0;
  ZiStatus status = read_zifs_u64_file(anchor_path, sizeof anchor_path - 1u, &first_release);
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  if (ZiSucceeded(status)) {
    ZiStatus lookup = lookup_zifs_record(file_path, sizeof file_path - 1u, &record, &record_index);
    if (expected_complete) {
      status = lookup == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
    } else {
      status = ZiSucceeded(lookup) && record.file_type == ZI_FS_FILE_TYPE_REGULAR
                   ? ZI_STATUS_SUCCESS
                   : ZI_STATUS_CORRUPT_FILESYSTEM;
    }
  }
  if (ZiFailed(status)) {
    return status;
  }
  return prepare_zifs_reuse_probe(first_release, expected_complete);
}

static ZiStatus prepare_and_commit_zifs_truncate(const char* file_path,
                                                 size_t file_path_size,
                                                 uint64_t new_size,
                                                 uint64_t failure_offset,
                                                 ZiFsTruncateResult* out_result) {
  if (out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, file_path_size, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  ZiFsTruncateRequest request = {
      sizeof(ZiFsTruncateRequest),
      ZI_FS_TRUNCATE_REQUEST_VERSION,
      record_index,
      new_size,
      UINT64_C(23000000),
      ZI_FS_TRUNCATE_FLAG_NONE,
      0,
  };
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareTruncate(&transaction, &request, out_result);
  }
  if (ZiFailed(status) || transaction.deferred_extent_count == 0 ||
      out_result->released_block_count == 0) {
    return failure_status_or(status, ZI_STATUS_INVALID_STATE);
  }
  if (failure_offset != 0) {
    if (g_root_volume.device.context != &g_zifs_fault_context ||
        g_zifs_fault_context.fail_operation != UINT64_MAX) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_zifs_fault_context.operation_count = 0;
    g_zifs_fault_context.fail_operation = transaction.block_image_count + failure_offset;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (failure_offset == 0) {
    return status;
  }
  return status == ZI_STATUS_DEVICE_ERROR &&
                 g_zifs_fault_context.operation_count ==
                     (uint64_t)transaction.block_image_count + failure_offset &&
                 transaction.state == ZI_FS_TRANSACTION_STATE_FAILED
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_STATE;
}

static ZiStatus prepare_and_commit_zifs_delete(const char* parent_path,
                                               size_t parent_path_size,
                                               ZiStringView name,
                                               uint64_t failure_offset,
                                               ZiFsDeleteResult* out_result) {
  if (out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsFileRecord parent = {0};
  uint64_t parent_record_index = 0;
  ZiStatus status =
      lookup_zifs_record(parent_path, parent_path_size, &parent, &parent_record_index);
  if (ZiFailed(status) || parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  ZiFsDeleteRequest request = {
      sizeof(ZiFsDeleteRequest),
      ZI_FS_DELETE_REQUEST_VERSION,
      parent_record_index,
      UINT64_C(24000000),
      ZI_FS_DELETE_FLAG_NONE,
      0,
      name,
  };
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareDelete(&transaction, &request, out_result);
  }
  if (ZiFailed(status) || transaction.deferred_extent_count == 0 ||
      out_result->released_block_count == 0) {
    return failure_status_or(status, ZI_STATUS_INVALID_STATE);
  }
  if (failure_offset != 0) {
    if (g_root_volume.device.context != &g_zifs_fault_context ||
        g_zifs_fault_context.fail_operation != UINT64_MAX) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_zifs_fault_context.operation_count = 0;
    g_zifs_fault_context.fail_operation = transaction.block_image_count + failure_offset;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (failure_offset == 0) {
    return status;
  }
  return status == ZI_STATUS_DEVICE_ERROR &&
                 g_zifs_fault_context.operation_count ==
                     (uint64_t)transaction.block_image_count + failure_offset &&
                 transaction.state == ZI_FS_TRANSACTION_STATE_FAILED
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_STATE;
}

static ZiStatus prepare_and_commit_zifs_create(const char* parent_path,
                                               size_t parent_path_size,
                                               ZiStringView name,
                                               ZiConstBuffer data,
                                               ZiFsCreateResult* out_result) {
  if (out_result == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsFileRecord parent = {0};
  uint64_t parent_record_index = 0;
  ZiStatus status =
      lookup_zifs_record(parent_path, parent_path_size, &parent, &parent_record_index);
  if (ZiFailed(status) || parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  ZiFsCreateRequest request = {
      sizeof(ZiFsCreateRequest),
      ZI_FS_CREATE_REQUEST_VERSION,
      parent_record_index,
      parent.security_id,
      UINT64_C(25000000),
      name,
      data,
  };
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareCreateFile(&transaction, &request, out_result);
  }
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionCommit(&transaction);
  }
  return status;
}

static ZiStatus
verify_zifs_truncated_pe(const char* file_path, size_t file_path_size, uint64_t expected_size) {
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, file_path_size, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      record.file_size != expected_size || record.extent_count == 0) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        g_zifs_test_readback,
                        2,
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  return ZiSucceeded(status) && bytes_read == 2 && g_zifs_test_readback[0] == 'M' &&
                 g_zifs_test_readback[1] == 'Z'
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus
read_zifs_u64_file(const char* file_path, size_t file_path_size, uint64_t* out_value) {
  if (out_value == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, file_path_size, &record, &record_index);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      record.file_size != sizeof(uint64_t)) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        g_zifs_test_readback,
                        sizeof(uint64_t),
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  if (ZiFailed(status) || bytes_read != sizeof(uint64_t)) {
    return failure_status_or(status, ZI_STATUS_CORRUPT_FILESYSTEM);
  }
  *out_value = zi_read_u64_le(g_zifs_test_readback);
  return ZI_STATUS_SUCCESS;
}

static ZiStatus prepare_zifs_reuse_probe(uint64_t forbidden_or_expected_block, bool expect_reuse) {
  const char parent_path[] = "C:\\Temp";
  const ZiStringView name = {"Deferred Reuse Probe.bin", sizeof "Deferred Reuse Probe.bin" - 1u};
  const unsigned char value = UINT8_C(0x21);
  ZiFsFileRecord parent = {0};
  uint64_t parent_record_index = 0;
  ZiStatus status =
      lookup_zifs_record(parent_path, sizeof parent_path - 1u, &parent, &parent_record_index);
  ZiFsTransaction transaction = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionInitialise(&transaction,
                                       &g_root_volume,
                                       g_zifs_transaction_workspace,
                                       sizeof g_zifs_transaction_workspace);
  }
  ZiFsCreateRequest request = {
      sizeof(ZiFsCreateRequest),
      ZI_FS_CREATE_REQUEST_VERSION,
      parent_record_index,
      parent.security_id,
      UINT64_C(26000000),
      name,
      {&value, 1},
  };
  ZiFsCreateResult result = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareCreateFile(&transaction, &request, &result);
  }
  if (ZiFailed(status) || result.data_block_count != 1) {
    return failure_status_or(status, ZI_STATUS_INVALID_STATE);
  }
  bool reused = result.first_data_block == forbidden_or_expected_block;
  return reused == expect_reuse ? ZI_STATUS_SUCCESS : ZI_STATUS_INVALID_STATE;
}

// The fault wrapper is armed only after all read-only preparation has completed.
// NOLINTNEXTLINE(readability-function-size, readability-function-cognitive-complexity)
static ZiStatus prepare_and_commit_zifs_move(const char* source_parent_path,
                                             size_t source_parent_path_size,
                                             ZiStringView source_name,
                                             const char* target_parent_path,
                                             size_t target_parent_path_size,
                                             ZiStringView target_name,
                                             uint32_t expected_image_count,
                                             uint64_t fail_operation) {
  ZiFsFileRecord source_parent = {0};
  ZiFsFileRecord target_parent = {0};
  uint64_t source_parent_record_index = 0;
  uint64_t target_parent_record_index = 0;
  ZiStatus status = lookup_zifs_record(source_parent_path,
                                       source_parent_path_size,
                                       &source_parent,
                                       &source_parent_record_index);
  if (ZiSucceeded(status)) {
    status = lookup_zifs_record(target_parent_path,
                                target_parent_path_size,
                                &target_parent,
                                &target_parent_record_index);
  }
  if (ZiFailed(status) || source_parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY ||
      target_parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiFsTransaction transaction = {0};
  status = ZiFsTransactionInitialise(&transaction,
                                     &g_root_volume,
                                     g_zifs_transaction_workspace,
                                     sizeof g_zifs_transaction_workspace);
  ZiFsMoveRequest request = {
      sizeof(ZiFsMoveRequest),
      ZI_FS_MOVE_REQUEST_VERSION,
      source_parent_record_index,
      target_parent_record_index,
      UINT64_C(22000000),
      ZI_FS_MOVE_FLAG_NONE,
      0,
      source_name,
      target_name,
  };
  ZiFsMoveResult result = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsTransactionPrepareMove(&transaction, &request, &result);
  }
  if (ZiFailed(status)) {
    return status;
  }
  if (transaction.block_image_count != expected_image_count || result.file_id == 0 ||
      result.record_index == g_root_volume.superblock.root_record_index ||
      result.source_parent_file_id != source_parent.file_id ||
      result.target_parent_file_id != target_parent.file_id ||
      result.file_type != ZI_FS_FILE_TYPE_REGULAR) {
    return ZI_STATUS_INVALID_STATE;
  }

  if (fail_operation != 0) {
    if (g_root_volume.device.context != &g_zifs_fault_context || fail_operation == UINT64_MAX) {
      return ZI_STATUS_INVALID_STATE;
    }
    g_zifs_fault_context.operation_count = 0;
    g_zifs_fault_context.fail_operation = fail_operation;
  }
  status = ZiFsTransactionCommit(&transaction);
  if (fail_operation == 0) {
    return status;
  }
  return status == ZI_STATUS_DEVICE_ERROR &&
                 g_zifs_fault_context.operation_count == fail_operation &&
                 transaction.state == ZI_FS_TRANSACTION_STATE_FAILED
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_INVALID_STATE;
}

static ZiStatus lookup_zifs_record(const char* path_text,
                                   size_t path_size,
                                   ZiFsFileRecord* out_record,
                                   uint64_t* out_record_index) {
  if (path_text == NULL || path_size == 0 || out_record == NULL || out_record_index == NULL) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStringView components[8] = {0};
  ZiParsedPath path = {0};
  ZiStatus status = zi_path_parse_absolute(path_text,
                                           path_size,
                                           components,
                                           sizeof components / sizeof components[0],
                                           &path);
  if (ZiFailed(status)) {
    return status;
  }
  return ZiFsLookupPathRecord(&g_root_volume,
                              &path,
                              g_zifs_block_buffer,
                              sizeof g_zifs_block_buffer,
                              out_record,
                              out_record_index);
}

static ZiStatus verify_zifs_pe_path(const char* file_path,
                                    size_t file_path_size,
                                    const char* parent_path,
                                    size_t parent_path_size,
                                    bool expected_present) {
  ZiFsFileRecord record = {0};
  uint64_t record_index = 0;
  ZiStatus status = lookup_zifs_record(file_path, file_path_size, &record, &record_index);
  if (!expected_present) {
    return status == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.file_size < 2 ||
      record.extent_count == 0 || record.security_id == 0 ||
      record_index == g_root_volume.superblock.root_record_index) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  ZiFsFileRecord parent = {0};
  uint64_t parent_record_index = 0;
  status = lookup_zifs_record(parent_path, parent_path_size, &parent, &parent_record_index);
  if (ZiFailed(status) || parent.file_type != ZI_FS_FILE_TYPE_DIRECTORY ||
      record.parent_file_id != parent.file_id) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        g_zifs_test_readback,
                        2,
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  return ZiSucceeded(status) && bytes_read == 2 && g_zifs_test_readback[0] == 'M' &&
                 g_zifs_test_readback[1] == 'Z'
             ? ZI_STATUS_SUCCESS
             : ZI_STATUS_CORRUPT_FILESYSTEM;
}

static ZiStatus verify_zifs_named_file(const char* file_path,
                                       size_t file_path_size,
                                       ZiConstBuffer expected_data,
                                       bool expected_present) {
  if (file_path == NULL || file_path_size == 0 ||
      (expected_data.data == NULL && expected_data.size != 0)) {
    return ZI_STATUS_INVALID_ARGUMENT;
  }
  ZiStringView components[1] = {0};
  ZiParsedPath path = {0};
  ZiStatus status = zi_path_parse_absolute(file_path,
                                           file_path_size,
                                           components,
                                           sizeof components / sizeof components[0],
                                           &path);
  ZiFsFileRecord record = {0};
  if (ZiSucceeded(status)) {
    status = ZiFsLookupPath(&g_root_volume,
                            &path,
                            g_zifs_block_buffer,
                            sizeof g_zifs_block_buffer,
                            &record);
  }
  if (!expected_present) {
    return status == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR ||
      record.file_size != expected_data.size) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }
  size_t offset = 0;
  while (offset < expected_data.size) {
    size_t chunk_size = expected_data.size - offset;
    if (chunk_size > sizeof g_zifs_test_readback) {
      chunk_size = sizeof g_zifs_test_readback;
    }
    size_t bytes_read = 0;
    status = ZiFsReadFile(&g_root_volume,
                          &record,
                          offset,
                          g_zifs_test_readback,
                          chunk_size,
                          &bytes_read,
                          g_zifs_block_buffer,
                          sizeof g_zifs_block_buffer);
    if (ZiFailed(status) || bytes_read != chunk_size ||
        zi_memory_compare(g_zifs_test_readback,
                          (const unsigned char*)expected_data.data + offset,
                          chunk_size) != 0) {
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    offset += chunk_size;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus mount_root_module(const ZiBootContext* context) {
  const ZiBootModule* module = find_zifs_module(context);
  if (module == NULL || module->size < UINT64_C(2) * ZI_FS_BLOCK_SIZE ||
      module->size % ZI_FS_BLOCK_SIZE != 0) {
    return ZI_STATUS_NOT_FOUND;
  }
  g_module_block_context.data = module->address;
  g_module_block_context.size = (size_t)module->size;
  ZiBlockDevice device = {
      sizeof(ZiBlockDevice),
      ZI_BLOCK_DEVICE_VERSION,
      &g_module_block_context,
      ZI_FS_BLOCK_SIZE,
      module->size / ZI_FS_BLOCK_SIZE,
      boot_module_read,
      NULL,
      ZI_BLOCK_DEVICE_READ_ONLY,
      NULL,
  };
  return mount_root_block_device(&device);
}

static void log_storage_progress(uint32_t completed_flags) {
  if ((completed_flags & ZI_STORAGE_COMPLETED_MANAGERS) != 0) {
    zi_log_boot_marker("IO_MANAGER");
    zi_log_boot_marker("DMA_READY");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_ACPI) != 0) {
    zi_log_boot_marker("ACPI_READY");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_PCIE) != 0) {
    zi_log_boot_marker("PCIE_ENUMERATED");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_DEVICES) != 0) {
    zi_log_boot_marker("PCI_DEVICES");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_NVME) != 0) {
    zi_log_boot_marker("NVME_READY");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_GPT) != 0) {
    zi_log_boot_marker("GPT_ZIFS");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_PARTITION) != 0) {
    zi_log_boot_marker("ZIFS_PARTITION");
  }
  if ((completed_flags & ZI_STORAGE_COMPLETED_READ_STRESS) != 0) {
    zi_log_boot_marker("STORAGE_READ_STRESS");
  }
}

static ZiStatus verify_case_sensitive_lookup(void) {
  ZiStringView components[2] = {0};
  ZiParsedPath path = {0};
  const char expected_path[] = "C:\\Temp";
  ZiStatus status =
      zi_path_parse_absolute(expected_path, sizeof expected_path - 1, components, 2, &path);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsFileRecord record = {0};
  status = ZiFsLookupPath(&g_root_volume,
                          &path,
                          g_zifs_block_buffer,
                          sizeof g_zifs_block_buffer,
                          &record);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_DIRECTORY) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  const char wrong_case_path[] = "C:\\temp";
  status =
      zi_path_parse_absolute(wrong_case_path, sizeof wrong_case_path - 1, components, 2, &path);
  if (ZiFailed(status)) {
    return status;
  }
  status = ZiFsLookupPath(&g_root_volume,
                          &path,
                          g_zifs_block_buffer,
                          sizeof g_zifs_block_buffer,
                          &record);
  return status == ZI_STATUS_NOT_FOUND ? ZI_STATUS_SUCCESS : ZI_STATUS_CASE_MISMATCH;
}

static ZiStatus verify_zifs_security(void) {
  ZiFsFileRecord root = {0};
  ZiStatus status = ZiFsReadFileRecord(&g_root_volume,
                                       g_root_volume.superblock.root_record_index,
                                       g_zifs_block_buffer,
                                       sizeof g_zifs_block_buffer,
                                       &root);
  if (ZiFailed(status) || root.security_id == 0) {
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  const ZiAccessToken system_token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_SYSTEM, 1},
      NULL,
      0,
      0,
  };
  const ZiSecurityId users_group[] = {{ZI_SECURITY_AUTHORITY_GROUP, 2}};
  const ZiAccessToken user_token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 21},
      users_group,
      1,
      0,
  };
  const ZiSecurityId guests_group[] = {{ZI_SECURITY_AUTHORITY_GROUP, 3}};
  const ZiAccessToken guest_token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 22},
      guests_group,
      1,
      0,
  };
  const ZiAccessToken unlisted_token = {
      sizeof(ZiAccessToken),
      ZI_ACCESS_TOKEN_VERSION,
      {ZI_SECURITY_AUTHORITY_USER, 23},
      NULL,
      0,
      0,
  };
  ZiAccessMask granted = 0;
  status = ZiFsCheckSecurityAccess(&g_root_volume,
                                   root.security_id,
                                   &system_token,
                                   ZI_ACCESS_FULL_CONTROL,
                                   &granted,
                                   g_zifs_block_buffer,
                                   sizeof g_zifs_block_buffer);
  if (ZiFailed(status) || granted != ZI_ACCESS_FULL_CONTROL) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  const ZiAccessMask ordinary_access = ZI_ACCESS_READ | ZI_ACCESS_EXECUTE | ZI_ACCESS_LIST;
  status = ZiFsCheckSecurityAccess(&g_root_volume,
                                   root.security_id,
                                   &user_token,
                                   ordinary_access,
                                   &granted,
                                   g_zifs_block_buffer,
                                   sizeof g_zifs_block_buffer);
  if (ZiFailed(status) || granted != ordinary_access) {
    return ZI_STATUS_ACCESS_DENIED;
  }
  status = ZiFsCheckSecurityAccess(&g_root_volume,
                                   root.security_id,
                                   &guest_token,
                                   ZI_ACCESS_WRITE,
                                   &granted,
                                   g_zifs_block_buffer,
                                   sizeof g_zifs_block_buffer);
  if (status != ZI_STATUS_ACCESS_DENIED || granted != 0) {
    return ZI_STATUS_INVALID_STATE;
  }
  status = ZiFsCheckSecurityAccess(&g_root_volume,
                                   root.security_id,
                                   &unlisted_token,
                                   ZI_ACCESS_READ,
                                   &granted,
                                   g_zifs_block_buffer,
                                   sizeof g_zifs_block_buffer);
  return status == ZI_STATUS_ACCESS_DENIED && granted == 0 ? ZI_STATUS_SUCCESS
                                                           : ZI_STATUS_INVALID_STATE;
}

static ZiStatus verify_zifs_file_read(void) {
  ZiStringView components[4] = {0};
  ZiParsedPath path = {0};
  const char image_path[] = "C:\\Zizium\\System\\hello_standard.exe";
  ZiStatus status =
      zi_path_parse_absolute(image_path, sizeof image_path - 1u, components, 4, &path);
  if (ZiFailed(status)) {
    return status;
  }
  ZiFsFileRecord record = {0};
  status = ZiFsLookupPath(&g_root_volume,
                          &path,
                          g_zifs_block_buffer,
                          sizeof g_zifs_block_buffer,
                          &record);
  if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_CORRUPT_FILESYSTEM;
  }

  unsigned char image_header[64] = {0};
  size_t bytes_read = 0;
  status = ZiFsReadFile(&g_root_volume,
                        &record,
                        0,
                        image_header,
                        sizeof image_header,
                        &bytes_read,
                        g_zifs_block_buffer,
                        sizeof g_zifs_block_buffer);
  if (ZiFailed(status)) {
    return status;
  }
  if (bytes_read != sizeof image_header || image_header[0] != 'M' || image_header[1] != 'Z') {
    return ZI_STATUS_BAD_IMAGE_FORMAT;
  }
  return ZI_STATUS_SUCCESS;
}

static ZiStatus verify_service_manifests(void) {
  static const char* const k_manifest_paths[CORE_SERVICE_MANIFEST_COUNT] = {
      "C:\\Zizium\\Services\\ServiceHost.zsvc",
      "C:\\Zizium\\Services\\SecurityHost.zsvc",
      "C:\\Zizium\\Services\\LogHost.zsvc",
      "C:\\Zizium\\Services\\MountHost.zsvc",
      "C:\\Zizium\\Services\\SessionHost.zsvc",
  };
  for (size_t index = 0; index < CORE_SERVICE_MANIFEST_COUNT; ++index) {
    ZiStringView components[4] = {0};
    ZiParsedPath path = {0};
    ZiStatus status = zi_path_parse_absolute(k_manifest_paths[index],
                                             text_size(k_manifest_paths[index]),
                                             components,
                                             sizeof components / sizeof components[0],
                                             &path);
    if (ZiFailed(status)) {
      return status;
    }
    ZiFsFileRecord record = {0};
    status = ZiFsLookupPath(&g_root_volume,
                            &path,
                            g_zifs_block_buffer,
                            sizeof g_zifs_block_buffer,
                            &record);
    if (ZiFailed(status) || record.file_type != ZI_FS_FILE_TYPE_REGULAR || record.file_size == 0 ||
        record.file_size > sizeof g_service_manifest_data[index]) {
      if (ZiFailed(status)) {
        return status;
      }
      return ZI_STATUS_INVALID_SERVICE_MANIFEST;
    }
    size_t bytes_read = 0;
    status = ZiFsReadFile(&g_root_volume,
                          &record,
                          0,
                          g_service_manifest_data[index],
                          (size_t)record.file_size,
                          &bytes_read,
                          g_zifs_block_buffer,
                          sizeof g_zifs_block_buffer);
    if (ZiFailed(status) || bytes_read != record.file_size) {
      if (ZiFailed(status)) {
        return status;
      }
      return ZI_STATUS_CORRUPT_FILESYSTEM;
    }
    status = zi_service_manifest_parse(g_service_manifest_data[index],
                                       bytes_read,
                                       g_service_dependencies[index],
                                       ZI_SERVICE_MAX_DEPENDENCIES,
                                       &g_service_manifests[index]);
    if (ZiFailed(status)) {
      return status;
    }
  }

  g_service_start_order_count = 0;
  ZiStatus status = zi_service_resolve_start_order(g_service_manifests,
                                                   CORE_SERVICE_MANIFEST_COUNT,
                                                   g_service_start_order,
                                                   CORE_SERVICE_MANIFEST_COUNT,
                                                   &g_service_start_order_count);
  if (ZiFailed(status) || g_service_start_order_count != CORE_SERVICE_MANIFEST_COUNT) {
    if (ZiFailed(status)) {
      return status;
    }
    return ZI_STATUS_INVALID_STATE;
  }
  for (size_t index = 0; index < g_service_start_order_count; ++index) {
    if (g_service_start_order[index] != index) {
      return ZI_STATUS_INVALID_STATE;
    }
  }
  return ZI_STATUS_SUCCESS;
}

static bool command_line_has_token(const char* command_line, const char* token) {
  if (command_line == NULL || token == NULL || *token == '\0') {
    return false;
  }
  size_t token_size = 0;
  while (token[token_size] != '\0') {
    ++token_size;
  }
  for (size_t offset = 0; command_line[offset] != '\0';) {
    while (command_line[offset] == ' ' || command_line[offset] == '\t') {
      ++offset;
    }
    if (command_line[offset] == '\0') {
      break;
    }
    size_t component_size = 0;
    while (command_line[offset + component_size] != '\0' &&
           command_line[offset + component_size] != ' ' &&
           command_line[offset + component_size] != '\t') {
      ++component_size;
    }
    if (component_size == token_size &&
        zi_memory_compare(command_line + offset, token, token_size) == 0) {
      return true;
    }
    offset += component_size;
  }
  return false;
}

static const char* memory_status_message(ZiStatus status) {
  switch (status) {
    case ZI_STATUS_INVALID_ARGUMENT:
      return "Memory initialisation rejected an invalid or unaligned boot range.";
    case ZI_STATUS_ADDRESS_CONFLICT:
      return "Memory initialisation found overlapping boot ranges.";
    case ZI_STATUS_BUFFER_TOO_SMALL:
      return "Memory inventory storage is too small for the boot map.";
    case ZI_STATUS_NO_MEMORY:
      return "No usable physical run can hold allocator metadata.";
    case ZI_STATUS_RESOURCE_IN_USE:
      return "Allocator metadata was not placed wholly in usable memory.";
    case ZI_STATUS_INVALID_STATE:
      return "A kernel or module page has inconsistent boot ownership.";
    case ZI_STATUS_OUT_OF_BOUNDS:
      return "A physical-memory address or size exceeds its validated range.";
    case ZI_STATUS_ALIGNMENT_ERROR:
      return "A memory address or size violates its required alignment.";
    case ZI_STATUS_MEMORY_CORRUPTION:
      return "Memory ownership or allocator metadata is corrupt.";
    case ZI_STATUS_PAGE_NOT_MAPPED:
      return "A required virtual-memory page is not mapped.";
    default:
      return "Memory initialisation returned an unrecognised failure status.";
  }
}

static const char* virtual_memory_stage_message(uint32_t stage) {
  switch (stage) {
    case ZI_KERNEL_VMM_STAGE_NX:
      return "Virtual-memory failure stage: NX capability.";
    case ZI_KERNEL_VMM_STAGE_ROOT:
      return "Virtual-memory failure stage: root page table.";
    case ZI_KERNEL_VMM_STAGE_KERNEL_PARSE:
      return "Virtual-memory failure stage: loaded PE kernel validation.";
    case ZI_KERNEL_VMM_STAGE_KERNEL_HEADERS:
      return "Virtual-memory failure stage: protected PE headers.";
    case ZI_KERNEL_VMM_STAGE_KERNEL_SECTION:
      return "Virtual-memory failure stage: protected PE section.";
    case ZI_KERNEL_VMM_STAGE_HHDM:
      return "Virtual-memory failure stage: higher-half direct map.";
    case ZI_KERNEL_VMM_STAGE_APIC:
      return "Virtual-memory failure stage: local-APIC device page.";
    case ZI_KERNEL_VMM_STAGE_CR3:
      return "Virtual-memory failure stage: CR3 activation.";
    case ZI_KERNEL_VMM_STAGE_VERIFY:
      return "Virtual-memory failure stage: active mapping verification.";
    default:
      return "Virtual-memory failure stage: unknown.";
  }
}

static bool text_equal(const char* left, const char* right) {
  if (left == NULL || right == NULL) {
    return false;
  }
  size_t index = 0;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) {
      return false;
    }
    ++index;
  }
  return left[index] == right[index];
}

static size_t text_size(const char* text) {
  size_t size = 0;
  if (text != NULL) {
    while (text[size] != '\0') {
      ++size;
    }
  }
  return size;
}

static bool text_ends_with(const char* text, const char* ending) {
  if (text == NULL || ending == NULL) {
    return false;
  }
  size_t text_size = 0;
  size_t ending_size = 0;
  while (text[text_size] != '\0') {
    ++text_size;
  }
  while (ending[ending_size] != '\0') {
    ++ending_size;
  }
  if (ending_size > text_size) {
    return false;
  }
  return zi_memory_compare(text + text_size - ending_size, ending, ending_size) == 0;
}
