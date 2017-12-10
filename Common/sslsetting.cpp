#include "sslsetting.h"
#include <openssl\ssl.h>
#include <thread>
#include <mutex>

static std::mutex *locks;
thread_local static size_t this_id = std::hash<std::thread::id>{}(std::this_thread::get_id());

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
void ssl_threadid_function(CRYPTO_THREADID * id) {
	CRYPTO_THREADID_set_numeric(id, this_id);
}
#else  
unsigned long ssl_threadid_function_deprecated() {
	return this_id;
}
#endif  

void ssl_locking_callback(int mode, int type, const char *file, int line) {
	if (mode & CRYPTO_LOCK) {
		locks[type].lock();
	}
	else {
		locks[type].unlock();
	}
}

namespace MyProxy {

	void openssl_config::thread_setup()
	{
		auto size = CRYPTO_num_locks();
		locks = new std::mutex[CRYPTO_num_locks()];
#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
		CRYPTO_THREADID_set_callback(ssl_threadid_function);
#else  
		CRYPTO_set_id_callback(ssl_threadid_function_deprecated);
#endif  
		CRYPTO_set_locking_callback(ssl_locking_callback);
	}
	void openssl_config::thread_cleanup()
	{
		CRYPTO_set_locking_callback(NULL);
		delete[] locks;
	}
}
