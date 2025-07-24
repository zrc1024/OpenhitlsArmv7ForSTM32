# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

cmake_minimum_required(VERSION 3.16 FATAL_ERROR)

project(openHiTLS)
set(HiTLS_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR})
set(HiTLS_BUILD_DIR ../build/openhitls)
file(REMOVE_RECURSE ${HiTLS_BUILD_DIR})
file(MAKE_DIRECTORY ${HiTLS_BUILD_DIR})
execute_process(COMMAND python3 ${HiTLS_SOURCE_ROOT_DIR}/configure.py -m
        --build_dir ${HiTLS_BUILD_DIR}
        --feature_config=config/json/STM32F4/STM32F4_feature_config.json
        --compile_config=config/json/STM32F4/STM32F4_compile_config.json
        --system none
)
include(${HiTLS_BUILD_DIR}/modules.cmake)
