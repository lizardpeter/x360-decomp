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
    # In Release, the old void indirect executor allowed a failed child to
    # report success to its parent; the primary queue then published WPTR
    # even when the remainder was never executed. Quarantine the faulted
    # ring generation until an explicit guest ring reinitialization.
    source=replace(source,"    RunPendingFns();\n\n    u32 write_ptr_index = write_ptr_index_.load();",
        """    RunPendingFns();

    if (primary_faulted_) {
      // Keep the worker alive for shutdown and explicit ring reprogramming,
      // but do not repeatedly execute a partially consumed command stream.
      rex::platform::Wait(write_ptr_index_event_.get(), true, std::chrono::milliseconds(5));
      continue;
    }
    u32 write_ptr_index = write_ptr_index_.load();""")
    source=replace(source,"    if (!worker_running_) break;\n    read_ptr_index_=completed_index;",
        "    if (!worker_running_) break;\n    if (primary_faulted_) continue;\n    read_ptr_index_=completed_index;")
    source=replace(source,"    read_ptr_index_=0;\n    write_ptr_index_.store(0);",
        "    primary_faulted_=false;\n    read_ptr_index_=0;\n    write_ptr_index_.store(0);")
    source=replace(source,"    primary_buffer_size_=static_cast<u32>(1) << (size_log2+3);",
        """    if (size_log2>28) {
      primary_buffer_size_=0;
      primary_faulted_=true;
      REXGPU_ERROR("METRO_GPU invalid ring size_log2={}",size_log2);
      return;
    }
    primary_buffer_size_=static_cast<u32>(1) << (size_log2+3);""")
    source=replace(source,"  u8* primary_buffer =\n      GetPhysicalForWrite(physical_memory_, primary_buffer_ptr_, primary_buffer_size_);",
        """  if (!primary_buffer_size_ || read_index>=primary_buffer_size_/sizeof(u32) ||
      write_index>=primary_buffer_size_/sizeof(u32)) {
    primary_faulted_=true;
    REXGPU_ERROR("METRO_GPU invalid ring indices read={} write={} bytes={}",
                 read_index,write_index,primary_buffer_size_);
    return read_index;
  }
  u8* primary_buffer =
      GetPhysicalForWrite(physical_memory_, primary_buffer_ptr_, primary_buffer_size_);""")
    source=replace(source,'    REXGPU_ERROR("primary ring buffer is outside physical memory");\n    return write_index;',
        '    REXGPU_ERROR("primary ring buffer is outside physical memory");\n    primary_faulted_=true;\n    return read_index;')
    source=replace(source,"reader.GetReadOffset(),reader.GetReadCount(),read_ptr_writeback_ptr_);\n      REX_ASSERT_ALWAYS();\n      break;",
        "reader.GetReadOffset(),reader.GetReadCount(),read_ptr_writeback_ptr_);\n      primary_faulted_=true;\n      return read_index;")
    source=replace(source,"void CommandProcessor::ExecuteIndirectBuffer(u32 ptr, u32 count) {",
        """bool CommandProcessor::ExecuteIndirectBuffer(u32 ptr, u32 count) {
  if (!count) return true;
  // The PM4 indirect size field is 20 bits; reject invalid callers before
  // multiplying the count or creating a zero-capacity RingBuffer.
  if (count>0xFFFFF) return false;""")
    source=replace(source,'    REXGPU_ERROR("indirect buffer is outside physical memory");\n    return;',
        '    REXGPU_ERROR("indirect buffer is outside physical memory");\n    return false;')
    source=replace(source,'      REXGPU_ERROR("indirect buffer failed to execute a packet");\n      REX_ASSERT_ALWAYS();\n      break;\n    }\n  } while (reader.GetReadCount());\n}',
        '      REXGPU_ERROR("indirect buffer failed to execute a packet");\n      return false;\n    }\n  } while (reader.GetReadCount());\n  return worker_running_;\n}')
    source=replace(source,"  u32 list_ptr = CPUToGPU(reader->ReadAndSwap<u32>());\n  u32 list_length = reader->ReadAndSwap<u32>();\n  REX_ASSERT((list_length & ~0xFFFFF) == 0);\n  list_length &= 0xFFFFF;\n  ExecuteIndirectBuffer(GPUToCPU(list_ptr), list_length);\n  return worker_running_;",
        """  if (count!=2) REXGPU_FAIL(false,"Invalid PM4 indirect packet count {}",count);
  u32 list_ptr = CPUToGPU(reader->ReadAndSwap<u32>());
  u32 list_length = reader->ReadAndSwap<u32>();
  if (list_length & ~0xFFFFF) REXGPU_FAIL(false,"Invalid PM4 indirect length {}",list_length);
  return ExecuteIndirectBuffer(GPUToCPU(list_ptr),list_length);""")
    source=replace(source,"bool CommandProcessor::ExecutePacket(memory::RingBuffer* reader) {\n  const u32 packet",
        "bool CommandProcessor::ExecutePacket(memory::RingBuffer* reader) {\n  if (reader->GetReadCount()<sizeof(u32)) return false;\n  const u32 packet")
    source=replace(source,"bool CommandProcessor::ExecutePacketType1(memory::RingBuffer* reader, u32 packet) {\n  u32 reg_index_1",
        """bool CommandProcessor::ExecutePacketType1(memory::RingBuffer* reader, u32 packet) {
  if (reader->GetReadCount()<2*sizeof(u32))
    REXGPU_FAIL(false,"Truncated PM4 type-1 packet");
  u32 reg_index_1""")
    # The SDK's circular offsets represent full and empty as the same pair.
    # Linear PM4 submissions must explicitly mark a full read span, rather
    # than relying on a forced first read of an apparently empty ring.
    source=replace(source,"  reader.SetWriteOffset(count * sizeof(u32));\n  do {",
        "  reader.SetFullReadRange();\n  do {") if source.count("  reader.SetWriteOffset(count * sizeof(u32));\n  do {")==1 else source.replace(
        "  reader.SetWriteOffset(count * sizeof(u32));\n  do {","  reader.SetFullReadRange();\n  do {")
    if source.count("  reader.SetFullReadRange();")!=2:
        raise ValueError("expected two original linear PM4 readers")
    source=replace(source,"void CommandProcessor::ExecutePacket(u32 ptr, u32 count) {\n  u8* packet_buffer",
        """void CommandProcessor::ExecutePacket(u32 ptr, u32 count) {
  if (!count || count>0xFFFFF) return;
  u8* packet_buffer""")
    stream=sdk/"include/rex/memory/stream.h"
    sh=stream.read_text()
    sh=replace(sh,"  bool IsEmpty() const { return read_offset_ == write_offset_; }",
        "  bool IsEmpty() const { return !full_read_span_ && read_offset_ == write_offset_; }")
    sh=replace(sh,"  void SetReadOffset(size_t offset) { read_offset_ = static_cast<RingSizeT>(offset) % capacity_; }",
        "  void SetReadOffset(size_t offset) { full_read_span_=false; read_offset_ = static_cast<RingSizeT>(offset) % capacity_; }")
    sh=replace(sh,"  RingSizeT GetReadCount() const {\n    RingSizeT read_offs",
        "  RingSizeT GetReadCount() const {\n    if (full_read_span_) return capacity_;\n    RingSizeT read_offs")
    sh=replace(sh,"  void SetWriteOffset(size_t offset) { write_offset_ = static_cast<RingSizeT>(offset) % capacity_; }",
        """  void SetWriteOffset(size_t offset) { full_read_span_=false; write_offset_ = static_cast<RingSizeT>(offset) % capacity_; }

  // A linear input occupies the entire backing span. The normal circular
  // offset pair (0,0) would otherwise be indistinguishable from empty.
  // This is read-only initialization, consumed on the first actual read.
  void SetFullReadRange() {
    read_offset_=write_offset_=0;
    full_read_span_=capacity_!=0;
  }""")
    sh=replace(sh,"  RingSizeT GetWriteCount() const {\n    RingSizeT read_offs",
        "  RingSizeT GetWriteCount() const {\n    if (full_read_span_) return 0;\n    RingSizeT read_offs")
    sh=replace(sh,"  RingSizeT write_offset_ = 0;\n};\n\n/** Reads a 32 bit value",
        "  RingSizeT write_offset_ = 0;\n  bool full_read_span_ = false;\n};\n\n/** Reads a 32 bit value")
    sh=replace(sh,"  REX_ASSERT(capacity_ >= 4);\n  RingSizeT read_offs",
        "  REX_ASSERT(capacity_ >= 4);\n  full_read_span_=false;\n  RingSizeT read_offs")
    rb=sdk/"src/base/ring_buffer.cpp"
    rs=rb.read_text()
    rs=replace(rs,"void RingBuffer::AdvanceRead(size_t count) {\n  RingSizeT cnt",
        "void RingBuffer::AdvanceRead(size_t count) {\n  if (count) full_read_span_=false;\n  RingSizeT cnt")
    rs=replace(rs,"void RingBuffer::EndRead(ReadRange read_range) {\n  if (read_range.second)",
        "void RingBuffer::EndRead(ReadRange read_range) {\n  if (read_range.first_length || read_range.second_length) full_read_span_=false;\n  if (read_range.second)")
    rs=replace(rs,"  RingSizeT cnt = static_cast<RingSizeT>(count);\n\n  if (read_offset_ < write_offset_) {",
        "  full_read_span_=false;\n  RingSizeT cnt = static_cast<RingSizeT>(count);\n\n  if (read_offset_ < write_offset_) {")
    stream.write_text(sh);rb.write_text(rs)
    h=sdk/"src/gpu/xenos/command_processor.h"
    header=h.read_text()
    header=replace(header,"  void ExecuteIndirectBuffer(u32 ptr, u32 length);",
        "  bool ExecuteIndirectBuffer(u32 ptr, u32 length);")
    header=replace(header,"  u32 primary_buffer_size_ = 0;",
        "  u32 primary_buffer_size_ = 0;\n  // Worker-owned: a failed ring cannot publish completion until reprogrammed.\n  bool primary_faulted_ = false;")
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
      const auto cl = regs.Get<xenos::reg::PA_CL_CLIP_CNTL>();
      const auto vertex_kill = vertex_shader->GetWritesPointSizeEdgeFlagKillVertex();
      const auto key = std::array<u64, 18>{
        vs, ps, index_count, static_cast<u32>(prim_type), wt, wb, st, sb, wo,
        clip.offset[0], clip.offset[1], clip.extent[0], clip.extent[1],
        viewport_info.xy_offset[0], viewport_info.xy_extent[0],
        regs.Get<xenos::reg::RB_SURFACE_INFO>().surface_pitch, cl.value, vertex_kill};
      static thread_local std::set<std::array<u64, 18>> seen;
      if (seen.size() < 512 && seen.insert(key).second) {
        REXGPU_INFO("METRO_TEXT_CLIP seq={} vs={:016X} ps={:016X} indices={} prim={} window_tl={:08X} window_br={:08X} screen_tl={:08X} screen_br={:08X} window_offset={:08X} x={} y={} w={} h={} viewport_x={} viewport_y={} viewport_w={} viewport_h={} pitch={} clip_control={:08X} user_clip_mask={} cull_only={} clip_disabled={} vertex_kill_or={} shader_point_edge_kill={}",
          seen.size(), vs, ps, index_count, static_cast<u32>(prim_type), wt, wb, st, sb, wo,
          clip.offset[0], clip.offset[1], clip.extent[0], clip.extent[1],
          viewport_info.xy_offset[0], viewport_info.xy_offset[1],
          viewport_info.xy_extent[0], viewport_info.xy_extent[1],
          regs.Get<xenos::reg::RB_SURFACE_INFO>().surface_pitch,cl.value,
          static_cast<unsigned>(cl.ucp_ena),static_cast<unsigned>(cl.ucp_cull_only_ena),
          static_cast<unsigned>(cl.clip_disable),static_cast<unsigned>(cl.vtx_kill_or),vertex_kill);
      }
    }
  }""")
    # Match the original vertex translator's cull-distance interface for
    # every primitive. Reject if ANY plane is negative for ALL vertices.
    helper=sdk/"src/gpu/xenos/geometry_cull.h"
    if helper.exists():raise ValueError("geometry cull helper already staged")
    helper.write_text("""#pragma once

namespace rex::gpu {
constexpr unsigned GeometryInputCullDistanceCount(bool user_cull,
                                                  unsigned user_count,
                                                  bool vertex_kill_and) {
  return (user_cull?user_count:0u)+unsigned(vertex_kill_and);
}

// Preconditions: first_plane<plane_count and vertex_count>0.
// Both the SPIR-V builder and the native boolean regression use this fold.
template<class Sample,class All,class Any>
auto GeometryAnyCullPlane(unsigned first_plane,unsigned plane_count,
                          unsigned vertex_count,Sample sample,All all,Any any) {
  auto reduce_plane=[&](unsigned plane) {
    auto result=sample(plane,0u);
    for(unsigned v=1;v<vertex_count;++v)result=all(result,sample(plane,v));
    return result;
  };
  auto result=reduce_plane(first_plane);
  for(unsigned p=first_plane+1;p<plane_count;++p)result=any(result,reduce_plane(p));
  return result;
}
}
""")
    pipeline=sdk/"src/gpu/xenos/vulkan/pipeline_cache.cpp"
    ps=pipeline.read_text()
    ps=replace(ps,'#include "gpu/xenos/draw_state.h"',
        '#include "gpu/xenos/draw_state.h"\n#include "gpu/xenos/geometry_cull.h"')
    ps=replace(ps,"  u32 cull_distance_count = point_user_cull_distance_count + key.has_vertex_kill_and;",
        """  const u32 cull_distance_count=GeometryInputCullDistanceCount(
      key.user_clip_plane_cull,key.user_clip_plane_count,key.has_vertex_kill_and);""")
    ps=replace(ps,"""    spv::Id cull_condition = spv::NoResult;
    u32 cull_distance_start = point_recalculate_cull_distances ? point_user_cull_distance_count : 0;
    if (cull_distance_start < cull_distance_count) {
      for (u32 i = cull_distance_start; i < cull_distance_count; ++i) {
        for (u32 j = 0; j < input_primitive_vertex_count; ++j) {
          id_vector_temp.clear();
          id_vector_temp.push_back(builder.makeIntConstant(static_cast<i32>(j)));
          id_vector_temp.push_back(const_member_in_gl_per_vertex_cull_distance);
          id_vector_temp.push_back(builder.makeIntConstant(static_cast<i32>(i)));
          spv::Id cull_distance_is_negative = builder.createBinOp(
              spv::OpFOrdLessThan, type_bool,
              builder.createLoad(builder.createAccessChain(spv::StorageClassInput, in_gl_per_vertex,
                                                           id_vector_temp),
                                 spv::NoPrecision),
              const_float_0);
          if (cull_condition != spv::NoResult) {
            cull_condition = builder.createBinOp(spv::OpLogicalAnd, type_bool, cull_condition,
                                                 cull_distance_is_negative);
          } else {
            cull_condition = cull_distance_is_negative;
          }
        }
      }""","""    u32 cull_distance_start = point_recalculate_cull_distances ? point_user_cull_distance_count : 0;
    if (cull_distance_start < cull_distance_count) {
      const spv::Id cull_condition=GeometryAnyCullPlane(
          cull_distance_start,cull_distance_count,input_primitive_vertex_count,
          [&](u32 plane,u32 vertex) {
            id_vector_temp.clear();
            id_vector_temp.push_back(builder.makeIntConstant(static_cast<i32>(vertex)));
            id_vector_temp.push_back(const_member_in_gl_per_vertex_cull_distance);
            id_vector_temp.push_back(builder.makeIntConstant(static_cast<i32>(plane)));
            return builder.createBinOp(
                spv::OpFOrdLessThan,type_bool,
                builder.createLoad(builder.createAccessChain(spv::StorageClassInput,in_gl_per_vertex,
                                                             id_vector_temp),spv::NoPrecision),
                const_float_0);
          },
          [&](spv::Id lhs,spv::Id rhs) {
            return builder.createBinOp(spv::OpLogicalAnd,type_bool,lhs,rhs);
          },
          [&](spv::Id lhs,spv::Id rhs) {
            return builder.createBinOp(spv::OpLogicalOr,type_bool,lhs,rhs);
          });""")
    pipeline.write_text(ps)
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
