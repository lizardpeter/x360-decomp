#!/usr/bin/env python3
"""Reset native Xenos ring ownership at original VdInitializeRingBuffer."""
import argparse
import subprocess
from pathlib import Path
from patch_rexglue_imports import REVISION

def replace(source,old,new):
    if source.count(old)!=1:raise ValueError("GPU ring patch anchor: "+old[:100])
    return source.replace(old,new,1)

def patch(sdk,tests):
    p=sdk/"src/gpu/xenos/command_processor.cpp"
    source=p.read_text()
    source=replace(source,"""void CommandProcessor::InitializeRingBuffer(u32 ptr, u32 size_log2) {
  CallInThreadNoWait([this, ptr, size_log2]() {
    read_ptr_index_ = 0;
    primary_buffer_ptr_ = ptr;
    primary_buffer_size_ = static_cast<u32>(1) << (size_log2 + 3);
  });
}""","""void CommandProcessor::InitializeRingBuffer(u32 ptr, u32 size_log2) {
  // Reprogramming the primary ring starts a new hardware queue. The old
  // read/write indices and its writeback address belong to the old queue.
  // Serialize initialization before the producer can publish new WPTR.
  CallInThreadAndWait([this, ptr, size_log2]() {
    const auto old_write=write_ptr_index_.load();
    REXGPU_INFO("METRO_GPU ring_init old_base={:08X} old_size={:08X} old_read={:08X} old_write={:08X} old_writeback={:08X} new_base={:08X} size_log2={}",
                primary_buffer_ptr_,primary_buffer_size_,read_ptr_index_,old_write,
                read_ptr_writeback_ptr_,ptr,size_log2);
    if (primary_buffer_size_ && read_ptr_index_!=old_write && old_write!=0xBAADF00D)
      REXGPU_WARN("METRO_GPU explicit ring reinitialization with outstanding old commands");
    read_ptr_index_=0;
    write_ptr_index_.store(0);
    read_ptr_writeback_ptr_=0;
    read_ptr_update_freq_=0;
    primary_buffer_ptr_=ptr;
    primary_buffer_size_=static_cast<u32>(1) << (size_log2+3);
  });
}""")
    source=replace(source,"""void CommandProcessor::EnableReadPointerWriteBack(u32 ptr, u32 block_size_log2) {
  CallInThreadNoWait([this, ptr, block_size_log2]() {
    read_ptr_writeback_ptr_ = ptr;
    read_ptr_update_freq_ = static_cast<u32>(1) << block_size_log2 >> 2;
  });
}""","""void CommandProcessor::EnableReadPointerWriteBack(u32 ptr, u32 block_size_log2) {
  CallInThreadAndWait([this, ptr, block_size_log2]() {
    read_ptr_writeback_ptr_=ptr;
    read_ptr_update_freq_=static_cast<u32>(1) << block_size_log2 >> 2;
    if (ptr) StoreReleaseHost(physical_memory_,ptr,read_ptr_index_);
    REXGPU_INFO("METRO_GPU ring_writeback base={:08X} address={:08X} read={:08X}",
                primary_buffer_ptr_,ptr,read_ptr_index_);
  });
}""")
    source=replace(source,'      REXGPU_ERROR("primary ring buffer failed to execute a packet");',
        '''      REXGPU_ERROR("primary ring buffer failed to execute a packet");
      REXGPU_ERROR("METRO_GPU ring_fault base={:08X} size={:08X} read={:08X} write={:08X} packet_end={:08X} bytes_left={:08X} writeback={:08X}",
                   primary_buffer_ptr_,primary_buffer_size_,read_index,write_index,
                   reader.GetReadOffset(),reader.GetReadCount(),read_ptr_writeback_ptr_);''')
    source=replace(source,'REXGPU_FAIL(false, "ExecutePacketType3 overflow (read count {:08X}, packet count {:08X})",\n                reader->GetReadCount(), count * sizeof(u32));',
        '''REXGPU_FAIL(false, "ExecutePacketType3 overflow (read count {:08X}, packet count {:08X}, header {:08X}, opcode {:02X}, data offset {:08X})",
                reader->GetReadCount(), count * sizeof(u32),packet,opcode,data_start_offset);''')
    # WAIT_REG_MEM deliberately returns false when Shutdown stops the worker.
    # Unwind every enclosing stream without asserting or publishing completion
    # for commands that were not executed. Keep live packet failures fatal.
    source=replace(source,"    read_ptr_index_ = ExecutePrimaryBuffer(read_ptr_index_, write_ptr_index);\n\n    if (read_ptr_writeback_ptr_) {",
        """    const auto completed_index=ExecutePrimaryBuffer(read_ptr_index_, write_ptr_index);
    if (!worker_running_) break;
    read_ptr_index_=completed_index;

    if (read_ptr_writeback_ptr_) {""")
    for marker in ("primary ring buffer failed to execute a packet",
                   "indirect buffer failed to execute a packet",
                   "ExecutePacket failed to execute a packet"):
        source=replace(source,'    if (!ExecutePacket(&reader)) {\n      REXGPU_ERROR("'+marker+'");',
            '    if (!worker_running_) break;\n    if (!ExecutePacket(&reader)) {\n      if (!worker_running_) {\n        REXGPU_INFO("METRO_GPU packet_stream_cancelled during shutdown");\n        break;\n      }\n      REXGPU_ERROR("'+marker+'");')
    source=replace(source,"  OnPrimaryBufferEnd();\n\n  return write_index;",
        """  if (!worker_running_) return read_index;
  OnPrimaryBufferEnd();

  return write_index;""")
    source=replace(source,"  ExecuteIndirectBuffer(GPUToCPU(list_ptr), list_length);\n  return true;",
        "  ExecuteIndirectBuffer(GPUToCPU(list_ptr), list_length);\n  return worker_running_;")
    h=sdk/"src/gpu/xenos/command_processor.h"
    header=h.read_text()
    # Match only the public method's stale asynchronous documentation.
    header=replace(header,"read index is 0 once it returns to its loop, and the call does not wait for the worker.",
        "read and write indices are reset before the call returns, and the old writeback is retired.")
    header=replace(header,"Enables writing the read pointer back to memory. The worker applies it at its next loop, and\n   * the call does not wait for the worker.",
        "Enables writing the read pointer back to memory. Publishes the current read index before\n   * returning, so the producer may safely start the new queue.")
    t=sdk/"tests/unit/gpu/fence_endianness_test.cpp"
    test=t.read_text()
    if "metro_gpu_ring" in test:raise ValueError("already staged")
    # Opt-in bounded diagnostics for guest text clipping at 720p.  No draw
    # state is modified and no vertex data, textures or strings are logged.
    vk=sdk/"src/gpu/xenos/vulkan/command_processor.cpp"
    v=vk.read_text()
    v=replace(v,"#include <cstdint>","#include <cstdint>\n#include <cstdlib>\n#include <set>")
    v=replace(v,"  UpdateDynamicState(viewport_info, primitive_polygonal, normalized_depth_control);",r"""  UpdateDynamicState(viewport_info, primitive_polygonal, normalized_depth_control);

  // This is after guest scissor conversion, before the actual draw.
  // Keep a bounded census of distinct draw states intersecting the top UI band.
  static const bool metro_clip_trace = [] {
    const char* v = std::getenv("X360_METRO_TEXT_CLIP_TRACE");
    return v && v[0] == '1' && !v[1];
  }();
  if (metro_clip_trace && draw_resolution_scale_x == 1 && draw_resolution_scale_y == 1) {
    draw_state::Scissor clip;
    draw_state::GetScissor(regs, clip);
    if (clip.offset[1] < 180 && clip.offset[1] + clip.extent[1] > 80) {
      const auto wt = regs.Get<xenos::reg::PA_SC_WINDOW_SCISSOR_TL>().value;
      const auto wb = regs.Get<xenos::reg::PA_SC_WINDOW_SCISSOR_BR>().value;
      const auto st = regs.Get<xenos::reg::PA_SC_SCREEN_SCISSOR_TL>().value;
      const auto sb = regs.Get<xenos::reg::PA_SC_SCREEN_SCISSOR_BR>().value;
      const auto wo = regs.Get<xenos::reg::PA_SC_WINDOW_OFFSET>().value;
      const auto vs = vertex_shader->GetUcodeDataHash();
      const u64 ps = pixel_shader ? pixel_shader->GetUcodeDataHash() : 0;
      const auto key = std::array<u64, 16>{
        vs, ps, index_count, static_cast<u32>(prim_type), wt, wb, st, sb, wo,
        clip.offset[0], clip.offset[1], clip.extent[0], clip.extent[1],
        viewport_info.xy_offset[0], viewport_info.xy_extent[0],
        regs.Get<xenos::reg::RB_SURFACE_INFO>().surface_pitch};
      static thread_local std::set<std::array<u64, 16>> seen;
      if (seen.size() < 512 && seen.insert(key).second) {
        REXGPU_INFO("METRO_TEXT_CLIP seq={} vs={:016X} ps={:016X} indices={} prim={} window_tl={:08X} window_br={:08X} screen_tl={:08X} screen_br={:08X} window_offset={:08X} x={} y={} w={} h={} viewport_x={} viewport_y={} viewport_w={} viewport_h={} pitch={}",
          seen.size(), vs, ps, index_count, static_cast<u32>(prim_type), wt, wb, st, sb, wo,
          clip.offset[0], clip.offset[1], clip.extent[0], clip.extent[1],
          viewport_info.xy_offset[0], viewport_info.xy_offset[1],
          viewport_info.xy_extent[0], viewport_info.xy_extent[1],
          regs.Get<xenos::reg::RB_SURFACE_INFO>().surface_pitch);
      }
    }
  }""")
    p.write_text(source);h.write_text(header);t.write_text(test+"\n"+tests.read_text())
    vk.write_text(v)
def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("sdk",type=Path)
    p.add_argument("--tests",type=Path,required=True)
    a=p.parse_args()
    if subprocess.check_output(["git","-C",str(a.sdk),"rev-parse","HEAD"],text=True).strip()!=REVISION:
        raise ValueError("unexpected SDK revision")
    patch(a.sdk,a.tests)
    subprocess.run(["git","-C",str(a.sdk),"diff","--check"],check=True)
if __name__=="__main__":main()
