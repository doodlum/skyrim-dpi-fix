cmake_minimum_required(VERSION 3.21)

project(
	DPIScalingFix
	VERSION 1.0.0
	LANGUAGES CXX
)

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")
include(XSEPlugin)

target_link_libraries(
	${PROJECT_NAME} 
	PRIVATE
		Shlwapi.lib
)