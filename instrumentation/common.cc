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

#include "common.h"

#include <vector>
#include <map>
#include <iostream>
#include <fstream>

#include "logging.pb.h"
#include "symbols.h"

#ifndef _WIN32
int
GetPrivateProfileStringA(const char *appName,
			 const char *keyName,
			 const char *dfault,
			 char *returnString,
			 size_t nSize,
			 const char *fileName) {
	int ret = 0, lineno = 0;

	std::ifstream f(fileName);
	if (!f.is_open())
		return (0);

	std::string section("");
	std::string line;
	std::map<std::string, std::map<std::string,std::string> *> inimap;
	
	inimap[section] = new std::map<std::string, std::string>();

	while (std::getline(f, line)) {
		lineno++;
		
		// Trim the right side of the line
		std::size_t found = line.find_last_not_of(" \t\r\n");
		if (found == std::string::npos) {
			// line is blank.
			continue;
		}
		line.erase(found + 1);
		
		// Trim left side of line
		found = line.find_first_not_of(" \t\r\n");
		if (found == std::string::npos) {
			// line is blank?
			continue;
		}
		if (found > 0)
			line.erase(0, found-1);

		if (line[0] == ';' || line[0] == '#') {
			// comment, ignore
			continue;
		}
		
		if (line[0] == '[') {
			line.erase(0, 1);
			found = line.find_last_not_of("]");
			if (found == std::string::npos) {
				// No closing section bracket
				std::cerr << fileName << ":" << lineno
					  << ": missing section bracket ']'"
					  << std::endl;
				continue;
			}
			if (found + 1 != line.length() - 1) {
				// last ']' isn't at end
				std::cerr << fileName << ":" << lineno
					  << ": syntax error" << std::endl;
				continue;
			}

			section = line.erase(found + 1);
			if (inimap.count(section) == 0)
				inimap[section] = new std::map<std::string,
							       std::string>();
			continue;
		}

		// This should be key=value line
		found = line.find_first_of("=");
		if (found == std::string::npos) {
			std::cerr << fileName << ":" << lineno
				  << ": syntax error, missing '='"
				  << std::endl;
			continue;
		}
		
		std::string key = line.substr(0, found);
		key.erase(found);
		found = key.find_last_not_of(" \t\r\n");
		if (found == std::string::npos) {
			std::cerr << fileName << ":" << lineno
				  << ": syntax error, missing key"
				  << std::endl;
			continue;
		}
		key = key.substr(0, found+1);
		
		found = line.find_first_of("=");
		std::string val = line.substr(found, std::string::npos);
		val.erase(0, 1);
		found = val.find_first_not_of(" \t\r\n");
		if (found == std::string::npos) {
			std::cerr << fileName << ":" << lineno
				  << ": syntax error, missing value"
				  << std::endl;
			continue;
		}
		val = val.substr(found, std::string::npos);

		std::map<std::string, std::string> *m = inimap[section];
		m->insert(std::pair<std::string, std::string>(key, val));
	}
	
	std::map<std::string, std::map<std::string,std::string> *>::iterator it;

	bool found = false;
	char *str = NULL;

	it = inimap.find(appName);
	if (it != inimap.end() && it->second != NULL) {
		std::map<std::string, std::string> *m = it->second;
		std::map<std::string,std::string>::iterator it2 = m->find(keyName);
		if (it2 != m->end()) {
			strncpy(returnString, it2->second.c_str(), nSize);
			// XXX check for overflow
			returnString[nSize-1] = '\0';
			found = true;
			ret = strlen(returnString);
		}
	}

	if (!found) {
		// XXX check for overflow
		if (dfault == NULL)
			dfault = "";
		strncpy(returnString, dfault, nSize);
		returnString[nSize-1] = '\0';
		ret = strlen(returnString);
	}
	
	while (!inimap.empty()) {
		it = inimap.begin();
		inimap[it->first] = NULL;
		delete it->second;
		inimap.erase(it->first);
	}
	
	if (f.is_open())
		f.close();
	
	return ret;
}
#endif

// See instrumentation.h for globals' documentation.
namespace globals {
  kfetch_config config;
  std::vector<module_info *> *special_modules;
  std::vector<module_info *> *modules;
  std::map<client_id, thread_info> thread_states;

  log_data_st last_ld;
  bool last_ld_present;

  bool has_instr_before_execution_handler;

namespace online {
  std::set<bx_address> known_callstack_item;
}  // namespace online

}  // namespace globals

// Debugging helper function.
int dbg_print(const char *fmt, ...) {
  va_list args;
  int ret = 0;

  va_start(args, fmt);
  ret = vfprintf(stderr, fmt, args);
  va_end(args);

  return ret;
}

// Given a kernel-mode virtual address, returns the image base of the
// corresponding module or NULL, if one is not found. Assuming that every
// executed address belongs to a valid PE address at any given time, not finding
// an address should be interpreted as a signal to update the current module
// database.
module_info* find_module(bx_address item) {
  unsigned int sz = globals::special_modules->size();

  // Prioritize the special_modules list, as it contains the most commonly
  // encountered images (e.g. ntoskrnl, win32k for Windows).
  for (unsigned int i = 0; i < sz; i++) {
    if (globals::special_modules->at(i)->module_base <= item &&
        globals::special_modules->at(i)->module_base + globals::special_modules->at(i)->module_size > item) {
      return globals::special_modules->at(i);
    }
  }

  // Search through the remaining known modules.
  sz = globals::modules->size();
  for (unsigned int i = 0; i < sz; i++) {
    if (globals::modules->at(i)->module_base <= item &&
        globals::modules->at(i)->module_base + globals::modules->at(i)->module_size > item) {
      return globals::modules->at(i);
    }
  }

  return NULL;
}

// Returns the contents of a single log record in formatted, textual form.
std::string LogDataAsText(const log_data_st& ld) {
  char buffer[256];
  std::string ret;

  snprintf(buffer, sizeof(buffer),
           "[pid/tid/ct: %.8x/%.8x/%.8x%.8x] {%16s} %.8x, %.8x: %s of %zx "
           "(%u * %u bytes), pc = %zx [ %40s ]\n",
           ld.process_id(), ld.thread_id(),
           (unsigned)(ld.create_time() >> 32),
           (unsigned)(ld.create_time()),
           ld.image_file_name().c_str(),
           (unsigned)ld.syscall_count(),
           (unsigned)ld.syscall_id(),
           translate_mem_access(ld.access_type()),
           ld.lin(),
           (unsigned)ld.repeated(),
           (unsigned)ld.len(),
           ld.pc(),
           ld.pc_disasm().c_str());
  ret = buffer;

  for (unsigned int i = 0; i < ld.stack_trace_size(); i++) {
    if (globals::config.symbolize) {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s)\n", i,
               (ld.stack_trace(i).module_base() + ld.stack_trace(i).relative_pc()),
               symbols::symbolize(ld.stack_trace(i).module_name(),
                                  ld.stack_trace(i).relative_pc()).c_str());
    } else {
      snprintf(buffer, sizeof(buffer), " #%u  0x%llx (%s+%.8x)\n", i,
               (ld.stack_trace(i).module_base() + ld.stack_trace(i).relative_pc()),
               ld.stack_trace(i).module_name().c_str(),
               (unsigned)ld.stack_trace(i).relative_pc());
    }
    ret += buffer;
  }

  return ret;
}

// Translate memory access type enum into textual representation.
const char *translate_mem_access(log_data_st::mem_access_type type) {
  switch (type) {
    case log_data_st::MEM_READ: return "READ";
    case log_data_st::MEM_WRITE: return "WRITE";
    case log_data_st::MEM_EXEC: return "EXEC";
    case log_data_st::MEM_RW: return "R/W";
  }
  return "INVALID";
}

