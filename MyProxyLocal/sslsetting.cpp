#include "sslsetting.h"
#include <openssl\ssl.h>
#include <thread>
#include <mutex>

#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
void ssl_threadid_function(CRYPTO_THREADID * id) {
	auto this_id = std::hash<std::thread::id>{}(std::this_thread::get_id());
	CRYPTO_THREADID_set_numeric(id, this_id);
}
#else  
unsigned long ssl_threadid_function_deprecated() {
	return std::hash<std::thread::id>{}(std::this_thread::get_id());
}
#endif  

std::vector<std::shared_ptr<std::mutex>> locks;

void ssl_locking_callback(int mode, int type, const char *file, int line) {
	if (mode & CRYPTO_LOCK) {
		//opensslLogger->trace("SSL lock");
		locks[type]->lock();
	}
	else {
		//opensslLogger->trace("SSL unlock");
		locks[type]->unlock();
	}
}

//void ssl_thread_setup() {
//	auto size = CRYPTO_num_locks();
//	for (size_t i = 0; i < size; i++) {
//		locks.push_back(std::make_shared<std::mutex>());
//	}
//#if OPENSSL_VERSION_NUMBER >= OPENSSL_VERSION_1_0_0  
//	CRYPTO_THREADID_set_callback(ssl_threadid_function);
//#else  
//	CRYPTO_set_id_callback(ssl_threadid_function_deprecated);
//#endif  
//	CRYPTO_set_locking_callback(ssl_locking_callback);
//}
//
//void ssl_thread_cleanup() {
//	CRYPTO_set_locking_callback(NULL);
//	locks.clear();
//}

namespace MyProxy {

	void openssl_config::thread_setup()
	{
		auto size = CRYPTO_num_locks();
		for (size_t i = 0; i < size; i++) {
			locks.push_back(std::make_shared<std::mutex>());
		}
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
		locks.clear();
	}
}
