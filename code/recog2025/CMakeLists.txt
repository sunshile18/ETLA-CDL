cmake_minimum_required(VERSION 3.5)

project(recog2025)

# Create a sources variable with a link to all cpp files to compile

set (location_sou
    src/location/main_location.cpp
    src/location/location_flow.cpp
    src/location/path_stat.cpp
)

IF (WIN32) 
    add_executable(location ${location_sou})
    target_include_directories(location PRIVATE ${PROJECT_SOURCE_DIR}/include)
    target_link_libraries(location 
        ${PROJECT_SOURCE_DIR}/lib/win/liblibconfig++.dll.a
        ${PROJECT_SOURCE_DIR}/lib/win/libFlow2SE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/libPcapSE.a
        ${PROJECT_SOURCE_DIR}/lib/win/libPacketSE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/libHashSE.a 
        ${PROJECT_SOURCE_DIR}/lib/win/lib_TLS2_SE.a )

ENDIF ()
