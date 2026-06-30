#include <filesystem>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

#include "measure/benchmark_ebpf.h"
#include "src/isa/ebpf/inst.h"
#include "src/isa/ebpf/inst_var.h"
#include "src/verify/validator.h"

void read_insns(inst** bm, const char* insn_file);

namespace {

namespace fs = std::filesystem;

constexpr int EXIT_PASS = 0;
constexpr int EXIT_FAIL = 1;
constexpr int EXIT_UNKNOWN = 2;

struct Args {
  fs::path old_path;
  fs::path new_path;
  fs::path map_path;
  fs::path desc_path;
  fs::path k2_root;
};

class ScopedCoutRedirect {
 public:
  ScopedCoutRedirect() : old_(std::cout.rdbuf(std::cerr.rdbuf())) {}
  ~ScopedCoutRedirect() { std::cout.rdbuf(old_); }

 private:
  std::streambuf* old_;
};

std::string json_escape(const std::string& input) {
  std::ostringstream out;
  for (char ch : input) {
    switch (ch) {
      case '\\':
        out << "\\\\";
        break;
      case '"':
        out << "\\\"";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        out << ch;
    }
  }
  return out.str();
}

void print_usage(const char* argv0) {
  std::cerr
      << "usage: " << argv0
      << " --old OLD.ins --new NEW.ins --map MAPS --desc DESC --k2-root DIR\n";
}

void emit_result(const std::string& result, const std::string& reason,
                 const Args& args, int old_len = -1, int new_len = -1) {
  std::cout << "{\n"
            << "  \"backend\": \"k2\",\n"
            << "  \"result\": \"" << result << "\",\n"
            << "  \"reason\": \"" << json_escape(reason) << "\",\n"
            << "  \"old\": \"" << json_escape(args.old_path.string()) << "\",\n"
            << "  \"new\": \"" << json_escape(args.new_path.string()) << "\",\n"
            << "  \"map\": \"" << json_escape(args.map_path.string()) << "\",\n"
            << "  \"desc\": \"" << json_escape(args.desc_path.string()) << "\",\n"
            << "  \"old_len\": " << old_len << ",\n"
            << "  \"new_len\": " << new_len << "\n"
            << "}\n";
}

Args parse_args(int argc, char** argv) {
  Args args;
  for (int i = 1; i < argc; i++) {
    std::string arg(argv[i]);
    auto require_value = [&](const std::string& name) -> std::string {
      if (i + 1 >= argc) {
        throw std::invalid_argument(name + " requires a value");
      }
      return argv[++i];
    };

    if (arg == "--old") {
      args.old_path = require_value(arg);
    } else if (arg == "--new") {
      args.new_path = require_value(arg);
    } else if (arg == "--map") {
      args.map_path = require_value(arg);
    } else if (arg == "--desc") {
      args.desc_path = require_value(arg);
    } else if (arg == "--k2-root") {
      args.k2_root = require_value(arg);
    } else if (arg == "--help" || arg == "-h") {
      print_usage(argv[0]);
      std::exit(EXIT_PASS);
    } else {
      throw std::invalid_argument("unknown argument: " + arg);
    }
  }

  if (args.old_path.empty() || args.new_path.empty() || args.map_path.empty() ||
      args.desc_path.empty()) {
    throw std::invalid_argument("missing required argument");
  }
  if (args.k2_root.empty()) {
    throw std::invalid_argument("missing --k2-root");
  }
  return args;
}

fs::path checked_absolute(const fs::path& path, const std::string& label) {
  if (!fs::exists(path)) {
    throw std::invalid_argument(label + " not found: " + path.string());
  }
  return fs::absolute(path);
}

Args normalize_args(const Args& input) {
  Args args = input;
  args.old_path = checked_absolute(args.old_path, "--old");
  args.new_path = checked_absolute(args.new_path, "--new");
  args.map_path = checked_absolute(args.map_path, "--map");
  args.desc_path = checked_absolute(args.desc_path, "--desc");
  args.k2_root = checked_absolute(args.k2_root, "--k2-root");
  return args;
}

void configure_k2() {
  validator::enable_z3server = false;
  smt_var::enable_multi_map_tables = true;
  smt_var::enable_multi_mem_tables = true;
  smt_var::enable_addr_off = true;
}

int run_equivalence(const Args& args) {
  inst* old_prog = nullptr;
  inst* new_prog = nullptr;
  int old_len = -1;
  int new_len = -1;
  int equal = -1;

  try {
    configure_k2();
    fs::current_path(args.k2_root);

    {
      ScopedCoutRedirect redirect;
      init_benchmark_from_file(&old_prog, args.old_path.c_str(),
                               args.map_path.c_str(), args.desc_path.c_str());
      old_len = inst::max_prog_len;
      convert_bpf_pgm_to_superopt_pgm(old_prog, old_len);

      read_insns(&new_prog, args.new_path.c_str());
      new_len = inst::max_prog_len;
      convert_bpf_pgm_to_superopt_pgm(new_prog, new_len);

      inst::max_prog_len = old_len;
      validator vld(old_prog, old_len);
      vld._enable_prog_eq_cache = false;
      equal = vld.is_equal_to(old_prog, old_len, new_prog, new_len);

      delete[] old_prog;
      old_prog = nullptr;
      delete[] new_prog;
      new_prog = nullptr;
    }

    if (equal == 1) {
      emit_result("PASS", "k2_equivalent", args, old_len, new_len);
      return EXIT_PASS;
    }
    if (equal == 0) {
      emit_result("FAIL", "k2_counterexample", args, old_len, new_len);
      return EXIT_FAIL;
    }

    emit_result("UNKNOWN", "k2_unsupported_or_illegal_program", args, old_len,
                new_len);
    return EXIT_UNKNOWN;
  } catch (const std::string& error) {
    delete[] old_prog;
    delete[] new_prog;
    emit_result("UNKNOWN", error, args, old_len, new_len);
    return EXIT_UNKNOWN;
  } catch (const std::exception& error) {
    delete[] old_prog;
    delete[] new_prog;
    emit_result("UNKNOWN", error.what(), args, old_len, new_len);
    return EXIT_UNKNOWN;
  } catch (...) {
    delete[] old_prog;
    delete[] new_prog;
    emit_result("UNKNOWN", "unknown K2 exception", args, old_len, new_len);
    return EXIT_UNKNOWN;
  }
}

}  // namespace

int main(int argc, char** argv) {
  try {
    Args args = normalize_args(parse_args(argc, argv));
    return run_equivalence(args);
  } catch (const std::exception& error) {
    print_usage(argv[0]);
    Args empty_args;
    emit_result("UNKNOWN", error.what(), empty_args);
    return EXIT_UNKNOWN;
  }
}
