#include "types.h"
#include "sh4_if.h"
#include "sh4_sched.h"
#include "cfg/cfg.h"
#include "cfg/option.h"

#include "sh4_mem.h"

using namespace config; // ✅ This line makes EnableFmvClockAdjust accessible

#include <algorithm>
#include <vector>
#include <cstdint>
#include <cstring>
#include <cstdio>

bool g_fmv_active = false;  // The *definition* (with initial value)

// FMV runtime SH4 clock scaling
constexpr u32 SH4_CLOCK_NORMAL = 200;
constexpr u32 SH4_CLOCK_FMV = 100;


bool g_mwply_scan_attempted = false;
bool g_mwply_second_attempted = false;
u32 g_detected_mwPlyStartFname = 0;
u32 g_executable_mwPlyStartFname = 0;
u32 g_executable_mwPlyEndFname = 0;
u32 g_sh4_cycle_count = 0;
extern u32 dynarec_block_counter;

extern "C" void MWCheckHook(u32 pc);



u64 last_fmv_tick = 0;

// Local state for sh4_sched.cpp (extern declarations, no initializer)
bool g_pending_resetcache = false;
u32 g_next_sh4_clock = SH4_CLOCK_NORMAL;



void ResetMWPlyDetection()
{
    if (g_fmv_active)
        printf("⚠️  [SFD] ResetMWPlyDetection called while FMV was still active!\n");

    g_mwply_scan_attempted = false;
    g_mwply_second_attempted = false;
    g_detected_mwPlyStartFname = 0;
    g_executable_mwPlyStartFname = 0;
    g_executable_mwPlyEndFname = 0;
    g_fmv_active = false;
    g_sh4_cycle_count = 0;
    last_fmv_tick = 0;
    dynarec_block_counter = 0;
//    g_pending_resetcache = true;

    printf("[SFD] FMV detection state reset.\n");
}







// ======================
// FMV Pattern Scanner
// ======================
const u32 ram_bases[] = { 0x0C000000, 0x8C000000 };  // 0x8C010000 is your refined search base
const u32 scan_start_offset = 0x00000000;
const u32 scan_end_offset   = 0x00300000;  // example: scan 0x1F0000 bytes (just under 2MB)  // default 0x00300000;

const u32 scan_size = scan_end_offset - scan_start_offset;

struct Pattern {
    const char* label;
    const uint8_t* bytes;
    size_t length;
    u32* result_var;
};

bool CheckMatchAndAssign(u8* ram, u32 base, u32 offset, const Pattern& pat) {
    if (memcmp(ram + offset, pat.bytes, pat.length) == 0) {
        u32 found_addr = base + offset;
        u32 exec_pc = 0x8C000000 | (found_addr & 0x00FFFFFF);
        *(pat.result_var) = exec_pc;

if ((found_addr & 0xFF000000) != 0x8C000000) // suppress 8C logs
{
    printf("[SFD] Detected %s at 0x%08X → PC=0x%08X (pattern match)\n",
           pat.label, found_addr, exec_pc);
}
        return true;
    }
    return false;
}

bool ScanRAMForPatterns(const Pattern* patterns, size_t pattern_count) {
    bool found_any = false;

    for (int i = 0; i < 2; ++i) {
        u32 base = ram_bases[i];
        u32 range = scan_end_offset - scan_start_offset;

        u8* ram = GetMemPtr(base + scan_start_offset, range);
        if (!ram) {
            printf("[SFD] ERROR: GetMemPtr failed for base 0x%08X + 0x%06X\n", base, scan_start_offset);
            continue;
        }

        for (u32 offset = 0; offset <= range - 16; ++offset) {
            for (size_t j = 0; j < pattern_count; ++j) {
                const Pattern& pat = patterns[j];
                if (offset + pat.length <= range &&
                    CheckMatchAndAssign(ram, base + scan_start_offset, offset, pat)) {
                    found_any = true;
                }
            }
        }
    }

    return found_any;
}

u32 FindMWPlyStartFname() {
    static u32 temp_result = 0;

    const Pattern patterns[] = {
        { "mwPlyStartFname (main)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xF8, 0x7F, 0x43, 0x6E, 0x52, 0x2F, 0xEF, 0x53 }, 14, &temp_result },
        { "mwPlyStartFname (alt1)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xF4, 0x7F, 0x43, 0x6E, 0xAB, 0xBB, 0x52, 0x2F }, 14, &temp_result },
        { "mwPlyStartFname (alt2)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x43, 0x6E, 0xC6, 0x2F, 0x53, 0x6D, 0x22, 0x4F, 0xFC, 0x7F }, 14, &temp_result },
        { "mwPlyStartFname (alt3)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xF4, 0x7F, 0x43, 0x6E, 0xBF, 0xBB, 0x52, 0x2F }, 14, &temp_result },
        { "mwPlyStartFname (alt4)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xF4, 0x7F, 0x43, 0x6E, 0xDE, 0xBB, 0x52, 0x2F }, 14, &temp_result },
        { "mwPlyStartFname (alt5)", (const uint8_t[]){ 0x22, 0x4F, 0xDC, 0x7F, 0x48, 0x1F, 0x57, 0x1F, 0xF8, 0x53, 0x36, 0x1F, 0xF6, 0x52 }, 14, &temp_result },
        { "mwPlyStartFname (alt6)", (const uint8_t[]){ 0xF4, 0x53, 0x36, 0x2F, 0x21, 0xD2, 0x26, 0x2F, 0x21, 0xD4, 0x21, 0xD3, 0x0B, 0x43 }, 14, &temp_result },
    };

    temp_result = 0;
    bool success = ScanRAMForPatterns(patterns, sizeof(patterns)/sizeof(Pattern));
    return success ? temp_result : 0;
}

u32 FindMWPlyEndFname() {
    static u32 temp_result = 0;

    const Pattern patterns[] = {
        { "mwSfdPause (main)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xF8, 0x7F, 0x43, 0x6E, 0xEC, 0x53 }, 12, &temp_result },
        { "mwSfdPause (alt1)", (const uint8_t[]){ 0xE6, 0x2F, 0xD6, 0x2F, 0x22, 0x4F, 0xFC, 0x7F, 0x43, 0x6E, 0xED, 0x5D }, 12, &temp_result },
        { "mwSfdPause (alt2)", (const uint8_t[]){ 0x27, 0xD3, 0x0B, 0x43, 0xF2, 0x64, 0x03, 0x64, 0x48, 0x24, 0x08, 0x89 }, 12, &temp_result },
        { "mwSfdPause (alt3)", (const uint8_t[]){ 0x1F, 0xB8, 0x09, 0x00, 0x02, 0x2F, 0x1A, 0xD3, 0x0B, 0x43, 0x09, 0x00 }, 12, &temp_result },
        { "mwSfdPause (alt4)", (const uint8_t[]){ 0x00, 0xE4, 0x17, 0xD3, 0x0B, 0x43, 0x09, 0x00, 0x01, 0xE4, 0x15, 0xD2 }, 12, &temp_result },
    };

    temp_result = 0;
    bool success = ScanRAMForPatterns(patterns, sizeof(patterns)/sizeof(Pattern));
    return success ? temp_result : 0;
}



// ======================
// Scheduler Logic Below
// ======================

//sh4 scheduler

/*
	register handler
	request callback at time

	single fire events only

	sh4_sched_register(id)
	sh4_sched_request(id, in_cycles)

	sh4_sched_now()
*/

u64 sh4_sched_ffb;
std::vector<sched_list> sch_list;
int sh4_sched_next_id = -1;

static u32 sh4_sched_now();

static u32 sh4_sched_remaining(const sched_list& sched, u32 reference)
{
	if (sched.end != -1)
		return sched.end - reference;
	else
		return -1;
}

void sh4_sched_ffts()
{
	u32 diff = -1;
	int slot = -1;

	u32 now = sh4_sched_now();
	for (const sched_list& sched : sch_list)
	{
		u32 remaining = sh4_sched_remaining(sched, now);
		if (remaining < diff)
		{
			slot = &sched - &sch_list[0];
			diff = remaining;
		}
	}

	sh4_sched_ffb -= Sh4cntx.sh4_sched_next;

	sh4_sched_next_id = slot;
	if (slot != -1)
		Sh4cntx.sh4_sched_next = diff;
	else
		Sh4cntx.sh4_sched_next = SH4_MAIN_CLOCK;

	sh4_sched_ffb += Sh4cntx.sh4_sched_next;
}

int sh4_sched_register(int tag, sh4_sched_callback* ssc)
{
	sched_list t{ ssc, tag, -1, -1 };
	for (sched_list& sched : sch_list)
		if (sched.cb == nullptr)
		{
			sched = t;
			return &sched - &sch_list[0];
		}

	sch_list.push_back(t);

	return sch_list.size() - 1;
}

void sh4_sched_unregister(int id)
{
	if (id == -1)
		return;
	verify(id < (int)sch_list.size());
	if (id == (int)sch_list.size() - 1)
		sch_list.resize(sch_list.size() - 1);
	else
	{
		sch_list[id].cb = nullptr;
		sch_list[id].end = -1;
	}
	sh4_sched_ffts();
}

/*
	Return current cycle count, in 32 bits (wraps after 21 dreamcast seconds)
*/
static u32 sh4_sched_now()
{
	return sh4_sched_ffb - Sh4cntx.sh4_sched_next;
}

/*
	Return current cycle count, in 64 bits (effectively never wraps)
*/
u64 sh4_sched_now64()
{
	return sh4_sched_ffb - Sh4cntx.sh4_sched_next;
}

void sh4_sched_request(int id, int cycles)
{
	verify(cycles == -1 || (cycles >= 0 && cycles <= SH4_MAIN_CLOCK));

	sched_list& sched = sch_list[id];
	sched.start = sh4_sched_now();

	if (cycles == -1)
	{
		sched.end = -1;
	}
	else
	{
		sched.end = sched.start + cycles;
		if (sched.end == -1)
			sched.end++;
	}

	sh4_sched_ffts();
}

/* Returns how much time has passed for this callback */
static int sh4_sched_elapsed(sched_list& sched)
{
	if (sched.end != -1)
	{
		int rv = sh4_sched_now() - sched.start;
		sched.start = sh4_sched_now();
		return rv;
	}
	else
		return -1;
}

static void handle_cb(sched_list& sched)
{
	int remain = sched.end - sched.start;
	int elapsd = sh4_sched_elapsed(sched);
	int jitter = elapsd - remain;

	sched.end = -1;
	int re_sch = sched.cb(sched.tag, remain, jitter);

	if (re_sch > 0)
		sh4_sched_request(&sched - &sch_list[0], std::max(0, re_sch - jitter));
}

// Clock switch helper
static void SetSh4Clock(u32 hz)
{
    config::Sh4Clock = hz;
    printf("⚙️  SH4 clock set to %u MHz %s\n", hz,
        g_fmv_active ? "(FMV active)" : "(FMV inactive)");
}

void sh4_sched_tick(int cycles)
{
//	printf("🔢 dynarec_block_counter = %u\n", dynarec_block_counter);
	if (Sh4cntx.sh4_sched_next >= 0)
		return;

	u32 fztime = sh4_sched_now() - cycles;

	if (sh4_sched_next_id != -1)
	{
		for (sched_list& sched : sch_list)
		{
			int remaining = sh4_sched_remaining(sched, fztime);
			if (remaining >= 0 && remaining <= (int)cycles)
				handle_cb(sched);
		}
	}

	sh4_sched_ffts();

	// ✅ Deferred ResetCache logic
	extern bool g_pending_resetcache;

// 🎯 One-time FMV scan attempt (adaptive threshold)
if (!g_mwply_scan_attempted)
{
    bool should_scan = false;

    if (config::UseReios && dynarec_block_counter > 300)
    {
        should_scan = true;
        printf("⚡ [sched ] HLE BIOS enabled — instant FMV scan triggered\n");
    }
    else if (dynarec_block_counter > 5000)
    {
        should_scan = true;
        printf("🔁 [sched ] Standard BIOS — delayed FMV scan triggered\n");
    }

    if (should_scan)
    {
        u32 pc = FindMWPlyStartFname();
        g_mwply_scan_attempted = true;

        if (pc)
        {
            g_executable_mwPlyStartFname = pc;
            printf("[FMV] Executable Start = 0x%08X\n", pc);

            u32 end_pc = FindMWPlyEndFname();
            if (end_pc)
            {
                g_executable_mwPlyEndFname = end_pc;
                printf("[FMV] ✅ FMV detection fully initialized.\n");
                printf("✅ [sched ] MWCheckHook setup successful at 0x%08X\n", pc);
            }
            else
            {
                printf("[FMV] ❌ FMV end not found — aborting hook setup.\n");
                g_executable_mwPlyStartFname = 0;
            }
        }
        else
        {
            printf("❌ [sched ] FMV pattern not found\n");
        }
    }
}

// 🎯 Second FMV scan attempt (for Sega logo path, ~few seconds into boot)
if (g_pending_resetcache)
	{
		if (EnableFmvClockAdjust)
		{
			printf("♻️  Resetting dynarec cache due to FMV trigger...\n");
			SetSh4Clock(g_next_sh4_clock);
			sh4_cpu.ResetCache();
		}
		else
		{
			printf("♻️  FMV clock adjust is disabled. Skipping clock change.\n");
		}
		g_pending_resetcache = false;
	}
}

extern u32 g_executable_mwPlyStartFname;
extern u32 g_executable_mwPlyEndFname;
constexpr u64 FMV_MIN_DURATION = 4000000; // ~0.25 seconds @ 200 MHz (tweak as needed)

extern "C" void MWCheckHook(u32 pc)
{
    // Normalize PC to mirror range (forces to 0x8Cxxxxxx)
    pc = 0x8C000000 | (pc & 0x00FFFFFF);

    if (!g_fmv_active && pc == g_executable_mwPlyStartFname)
    {
        printf("🎯 [RUNTIME] Hit mwPlyStartFname at PC=0x%08X\n", pc);
        g_fmv_active = true;
        last_fmv_tick = sh4_sched_now64();
        g_next_sh4_clock = SH4_CLOCK_FMV;
        g_pending_resetcache = true;
    }
    else if (g_fmv_active && pc == g_executable_mwPlyEndFname)
    {
        u64 now = sh4_sched_now64();
        if (now - last_fmv_tick < FMV_MIN_DURATION)
        {
            printf("⏱️  [RUNTIME] FMV end ignored — too soon (%llu cycles)\n", now - last_fmv_tick);
            return;
        }

        printf("🛑 [RUNTIME] FMV end at PC=0x%08X\n", pc);
        g_fmv_active = false;
        g_next_sh4_clock = SH4_CLOCK_NORMAL;
        g_pending_resetcache = true;
    }
    else if (!g_fmv_active && pc == g_executable_mwPlyEndFname)
    {
        printf("⚠️  [RUNTIME] FMV end triggered but FMV already inactive (PC=0x%08X)\n", pc);
    }
}




void sh4_sched_reset(bool hard)
{
	if (hard)
	{
		sh4_sched_ffb = 0;
		sh4_sched_next_id = -1;
		for (sched_list& sched : sch_list)
			sched.start = sched.end = -1;
		Sh4cntx.sh4_sched_next = 0;
	}
}
