#include "hphp/runtime/base/base-includes.h"
#include "hphp/runtime/base/runtime-error.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define NON_FREE
#define MCRYPT2
#include <mcrypt.h>

namespace HPHP {

///////////////////////////////////////////////////////////////////////////////

class MCrypt : public SweepableResourceData {
public:
  explicit MCrypt(MCRYPT td) : m_td(td), m_init(false) {
  }

  ~MCrypt() {
    MCrypt::close();
  }

  void sweep() FOLLY_OVERRIDE {
    close();
  }

  void close() {
    if (m_td != MCRYPT_FAILED) {
      mcrypt_generic_deinit(m_td);
      mcrypt_module_close(m_td);
      m_td = MCRYPT_FAILED;
    }
  }

  CLASSNAME_IS("mcrypt");
  // overriding ResourceData
  virtual const String& o_getClassNameHook() const { return classnameof(); }

  MCRYPT m_td;
  bool m_init;
};

typedef enum {
  RANDOM = 0,
  URANDOM,
  RAND
} iv_source;

class mcrypt_data {
public:
  std::string algorithms_dir;
  std::string modes_dir;
};
static mcrypt_data s_globals;
#define MCG(n) (s_globals.n)
#ifndef MIN
#define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif
#define MCRYPT_OPEN_MODULE_FAILED(str) \
 raise_warning("%s(): Module initialization failed", str);

bool HHVM_FUNCTION(mcrypt_module_is_block_algorithm_mode, const String& mode,
                                  const String& lib_dir /* = null_string */) {
  String dir = lib_dir.empty() ? String(MCG(modes_dir)) : lib_dir;
  return mcrypt_module_is_block_algorithm_mode((char*)mode.data(),
                                               (char*)dir.data()) == 1;
}

bool HHVM_FUNCTION(mcrypt_module_is_block_algorithm, const String& algorithm,
                                  const String& lib_dir /* = null_string */) {
  String dir = lib_dir.empty() ? String(MCG(algorithms_dir)) : lib_dir;
  return mcrypt_module_is_block_algorithm((char*)algorithm.data(),
                                          (char*)dir.data()) == 1;
}

bool HHVM_FUNCTION(mcrypt_module_is_block_mode, const String& mode,
                                   const String& lib_dir /* = null_string */) {
  String dir = lib_dir.empty() ? String(MCG(modes_dir)) : lib_dir;
  return mcrypt_module_is_block_mode((char*)mode.data(),
                                     (char*)dir.data()) == 1;
}

bool HHVM_FUNCTION(mcrypt_module_self_test, const String& algorithm,
                               const String& lib_dir /* = null_string */) {
  String dir = lib_dir.empty() ? String(MCG(algorithms_dir)) : lib_dir;
  return mcrypt_module_self_test((char*)algorithm.data(),
                                 (char*)dir.data()) == 0;
}

Variant HHVM_FUNCTION(mcrypt_create_iv, int size, int source /* = 0 */) {
  if (size <= 0 || size >= INT_MAX) {
    raise_warning("Can not create an IV with a size of less than 1 or "
                    "greater than %d", INT_MAX);
    return false;
  }

  int n = 0;
  char *iv = (char*)calloc(size + 1, 1);
  if (source == RANDOM || source == URANDOM) {
    int fd = open(source == RANDOM ? "/dev/random" : "/dev/urandom", O_RDONLY);
    if (fd < 0) {
      free(iv);
      raise_warning("Cannot open source device");
      return false;
    }
    int read_bytes;
    for (read_bytes = 0; read_bytes < size && n >= 0; read_bytes += n) {
      n = read(fd, iv + read_bytes, size - read_bytes);
    }
    n = read_bytes;
    close(fd);
    if (n < size) {
      free(iv);
      raise_warning("Could not gather sufficient random data");
      return false;
    }
  } else {
    n = size;
    while (size) {
      iv[--size] = (char)(255.0 * rand() / RAND_MAX);
    }
  }
  return String(iv, n, AttachString);
}
}