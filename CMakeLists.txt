cmake_minimum_required (VERSION 2.6)

project(zerof LANGUAGES CXX)

option(ZEROF_SOPATCH "Enables the prepatching (SONAME addition) code" OFF)
option(ZEROF_HOOKING "Enables the hooking code" ON)
add_library(zerof src/dlsym_helper.cpp src/lib_utils.cpp src/maps_helper.cpp)
if (ZEROF_SOPATCH)
  target_sources(zerof PRIVATE src/mem_so_patcher.cpp src/file_so_patcher.cpp src/soname_patch_creator.cpp)
endif()
if (ZEROF_HOOKING)
  target_sources(zerof PRIVATE src/reloc_hook_manager.cpp)
endif()
target_include_directories(zerof PUBLIC include/)
