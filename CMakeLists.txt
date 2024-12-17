cmake_minimum_required(VERSION 3.12)

project(
  example
  VERSION 0.1.0
  LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  add_compile_definitions(DEBUG)
elseif(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_definitions(RELEASE)
endif()

file(GLOB_RECURSE SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/src/*.c" "${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp")
file(GLOB_RECURSE HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/include/*.h" "${CMAKE_CURRENT_SOURCE_DIR}/include/*.hpp")

add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

add_subdirectory(deps/glfw)
add_subdirectory(deps/glad)
add_subdirectory(deps/freetype)

# disable harfbuzz for now
set(FT_DISABLE_HARFBUZZ ON CACHE BOOL "Disable HarfBuzz for FreeType" FORCE)
set(FT_DISABLE_BZIP2 ON CACHE BOOL "Disable BZip2 for FreeType" FORCE)
set(FT_DISABLE_BROTLI ON CACHE BOOL "Disable Brotli for FreeType" FORCE)
# Enable PNG support
set(FT_DISABLE_PNG ON CACHE BOOL "Enable PNG for FreeType" FORCE)
set(FT_DISABLE_ZLIB ON CACHE BOOL "Enable ZLib for FreeType" FORCE)

target_include_directories(${PROJECT_NAME} 
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
  PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${GLFW_INCLUDE_DIR}
    ${GLAD_INCLUDE_DIR}
    ${FREETYPE_INCLUDE_DIR} 
)

target_link_libraries(${PROJECT_NAME} 
  glfw
  glad
  freetype
)

# Force include GLAD before any other code
if(MSVC)
  target_compile_options(${PROJECT_NAME} PRIVATE /FI"glad/glad.h")
else()
  target_compile_options(${PROJECT_NAME} PRIVATE -include glad/glad.h)
endif()

target_compile_definitions(${PROJECT_NAME} PRIVATE GLAD_GL_IMPLEMENTATION)

