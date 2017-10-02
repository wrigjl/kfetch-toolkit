/////////////////////////////////////////////////////////////////////////
//
// Authors: Mateusz Jurczyk (mjurczyk@google.com)
//          Gynvael Coldwind (gynvael@google.com)
//
// Copyright 2013 Google Inc. All Rights Reserved.
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//     http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#ifndef KFETCH_TOOLKIT_OS_LINUX_H_
#define KFETCH_TOOLKIT_OS_LINUX_H_

#include <stdint.h>

#include "common.h"

namespace os_linux {

// ------------------------------------------------------------------
// System events public interface.
// ------------------------------------------------------------------
bool init(const char *, void *);
bool check_kernel_addr(uint64_t *, void *);
bool check_user_addr(uint64_t *, void *);
bool fill_cid(BX_CPU_C *, client_id *);
bool fill_info(BX_CPU_C *, void *);

}  // namespace linux

#endif  // KFETCH_TOOLKIT_OS_LINUX_H_

