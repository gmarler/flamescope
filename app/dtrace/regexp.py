import re
#
# Parsing
#
# This file is part of FlameScope, a performance analysis tool created by the
# Netflix cloud performance team. See:
#
#    https://github.com/Netflix/flamescope
#
# Copyright 2018 Netflix, Inc.
#
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License.

#
# This event_regexp matches the event line, and puts time in the first group:
#
event_regexp = re.compile(r"\s+([0-9.]+):$")
#
# For DTrace, the occurrence count for each stack
#
event_count_regexp = re.compile(r"^\s+(\d+)$")
#
# Matches a single stack frame
#
frame_regexp = re.compile(r"^([^`]+`|)([^+]+)(?:[+]0x[0-9a-fA-F]+)?$")
#
# Matches the 'comm'and or executable name of a process
#
comm_regexp = re.compile(r"^ *([^0-9]+)")
