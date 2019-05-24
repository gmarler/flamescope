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

import sys
import collections
from .regexp import event_regexp, event_count_regexp
from app.common.fileutil import get_file

# read and cache offsets
def dtrace_read_offsets(file_path):
    start = sys.maxsize
    end = 0
    offsets = []

    f = get_file(file_path)

    stack = ""
    ts = -1
    count = 0

    # process DTrace script output and search for:
    # - event_regexp: to identify event timestamps
    # this populates start, end, and offsets
    for line in f:
        if (line[0] == '#'):
            continue
        r = event_regexp.search(line)
        if (r):
            if (stack != ""):
                # process prior stack
                offsets.append([ts, count])
                # don't try to cache stacks (could be many Gbytes):
                stack = ""
            # Convert integer microsecs to seconds
            ts = int(r.group(1)) / 1000000
            if (ts < start):
                start = ts
            stack = line.rstrip()
        else:
            # If not an event, this is either a stack frame or the ending count of
            # occurrences of this stack
            cm = event_count_regexp.search(line)
            if (cm):
                count = int(cm.group(1))
            else:
                stack += line.rstrip()
    # last stack
    offsets.append([ts, count])
    if (ts > end):
        end = ts

    f.close()

    res = collections.namedtuple('offsets', ['start', 'end', 'offsets'])(start, end, offsets)
    return res
